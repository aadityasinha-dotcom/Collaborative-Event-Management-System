from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from bson import ObjectId
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from models import User, Project, Event, EventPermission, RecurrencePattern, EventHistory, Notification
from utils import role_required, event_permission_required, detect_event_conflicts, expand_recurring_events, generate_change_summary, reconstruct_event_state, generate_event_diff, determine_change_type
import mongoengine as me
import copy
import datetime

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "your_secret_key"
app.config["CONNECTION_STRING"] = "mongodb://localhost:27017/flaskApi"
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Connect to MongoDB using connection string
try:
    me.connect(host=app.config["CONNECTION_STRING"])
    print("Connected to MongoDB successfully.")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

def send_notification(user_id, message, notification_type, data=None):
    """
    Create and save a notification for a user
    
    Args:
        user_id (str): The ID of the user to notify
        message (str): The notification message
        notification_type (str): Type of notification
        data (dict, optional): Additional data for the notification
    
    Returns:
        Notification: The created notification object
    """
    if data is None:
        data = {}
        
    try:
        user = User.objects(id=ObjectId(user_id)).first()
        if not user:
            print(f"Warning: User not found for notification: {user_id}")
            return None
            
        notification = Notification(
            user=user,
            message=message,
            notification_type=notification_type,
            data=data
        )
        notification.save()
        
        # In a real-time system, you would emit an event here
        # For example, using Socket.IO or a message queue
        
        return notification
    except Exception as e:
        print(f"Error sending notification: {str(e)}")
        return None

# User Registration
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role', 'user')

        if User.objects(username=username):
            return jsonify({"message": "User already exists"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, password=hashed_password, role=role)
        user.save()

        return jsonify({"message": "User registered successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# User Login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')

        user = User.objects(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            token = create_access_token(identity={"username": username, "role": user.role, "user_id": str(user.id)})
            return jsonify({"access_token": token}), 200

        return jsonify({"message": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Health-check
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "OK"}), 200

# Event Management APIs

# Create Event
@app.route('/api/events', methods=['POST'])
@jwt_required()
def create_event():
    try:
        data = request.json
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        user = User.objects(id=ObjectId(user_id)).first()
        
        if not user:
            return jsonify({"message": "User not found"}), 404
            
        # Validate required fields
        required_fields = ['title', 'description', 'start_time', 'end_time']
        for field in required_fields:
            if field not in data:
                return jsonify({"message": f"Missing required field: {field}"}), 400
        
        # Parse datetime strings to datetime objects
        try:
            start_time = datetime.datetime.fromisoformat(data['start_time'])
            end_time = datetime.datetime.fromisoformat(data['end_time'])
        except ValueError:
            return jsonify({"message": "Invalid datetime format. Use ISO format (YYYY-MM-DDTHH:MM:SS)"}), 400
            
        # Check if end time is after start time
        if end_time <= start_time:
            return jsonify({"message": "End time must be after start time"}), 400
            
        # Check for conflicts
        conflicting_events = detect_event_conflicts(user_id, start_time, end_time)
        if conflicting_events:
            conflict_details = [{"id": str(e.id), "title": e.title, "start_time": e.start_time, "end_time": e.end_time} for e in conflicting_events]
            return jsonify({
                "message": "Event conflicts with existing events",
                "conflicts": conflict_details
            }), 409
            
        # Create recurrence pattern if applicable
        recurrence_pattern = None
        if data.get('is_recurring', False):
            if 'recurrence_pattern' not in data:
                return jsonify({"message": "Recurrence pattern is required for recurring events"}), 400
                
            pattern_data = data['recurrence_pattern']
            
            # Validate recurrence pattern
            if 'frequency' not in pattern_data:
                return jsonify({"message": "Frequency is required in recurrence pattern"}), 400
                
            # Convert end_date to datetime if present
            if 'end_date' in pattern_data:
                try:
                    pattern_data['end_date'] = datetime.datetime.fromisoformat(pattern_data['end_date'])
                except ValueError:
                    return jsonify({"message": "Invalid end_date format in recurrence pattern"}), 400
            
            recurrence_pattern = RecurrencePattern(**pattern_data)
        
        # Create the event
        event = Event(
            title=data['title'],
            description=data['description'],
            start_time=start_time,
            end_time=end_time,
            location=data.get('location', ''),
            created_by=user,
            is_recurring=data.get('is_recurring', False),
            recurrence_pattern=recurrence_pattern,
            permissions=[]  # Initial permissions (owner only)
        )
        
        event.save()
        
        return jsonify({
            "message": "Event created successfully",
            "event": {
                "id": str(event.id),
                "title": event.title,
                "description": event.description,
                "start_time": event.start_time.isoformat(),
                "end_time": event.end_time.isoformat(),
                "location": event.location,
                "is_recurring": event.is_recurring
            }
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get All Events with Filtering and Pagination
@app.route('/api/events', methods=['GET'])
@jwt_required()
def get_events():
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        # Pagination parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 10))
        
        # Filter parameters
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        title_search = request.args.get('title')
        
        # Build the query
        query = {
            "$or": [
                {"created_by": ObjectId(user_id)},  # Events created by the user
                {"permissions.user": ObjectId(user_id)}  # Events shared with the user
            ]
        }
        
        # Add date filters if provided
        date_filters = {}
        if start_date:
            try:
                start_date = datetime.datetime.fromisoformat(start_date)
                date_filters["end_time"] = {"$gte": start_date}
            except ValueError:
                return jsonify({"message": "Invalid start_date format"}), 400
                
        if end_date:
            try:
                end_date = datetime.datetime.fromisoformat(end_date)
                date_filters["start_time"] = {"$lte": end_date}
            except ValueError:
                return jsonify({"message": "Invalid end_date format"}), 400
                
        if date_filters:
            query.update(date_filters)
            
        # Add title search if provided
        if title_search:
            query["title"] = {"$regex": title_search, "$options": "i"}  # Case-insensitive search
        
        # Execute the query with pagination
        events = Event.objects(__raw__=query).skip((page - 1) * limit).limit(limit)
        
        # Get total count for pagination
        total = Event.objects(__raw__=query).count()
        
        # Format the response
        events_list = []
        for event in events:
            # Determine user's role for this event
            user_role = "owner" if str(event.created_by.id) == user_id else None
            
            if not user_role:
                for permission in event.permissions:
                    if str(permission.user.id) == user_id:
                        user_role = permission.role
                        break
            
            events_list.append({
                "id": str(event.id),
                "title": event.title,
                "description": event.description,
                "start_time": event.start_time.isoformat(),
                "end_time": event.end_time.isoformat(),
                "location": event.location,
                "is_recurring": event.is_recurring,
                "created_by": event.created_by.username,
                "user_role": user_role
            })
        
        # If date range specified and events are recurring, expand recurring events
        if start_date and end_date and events_list:
            expanded_events = []
            for event in events:
                if event.is_recurring:
                    instances = expand_recurring_events(event, start_date, end_date)
                    expanded_events.extend(instances)
                else:
                    # For non-recurring events, add them directly if they're in the date range
                    if event.start_time <= end_date and event.end_time >= start_date:
                        expanded_events.append({
                            "id": str(event.id),
                            "title": event.title,
                            "description": event.description,
                            "start_time": event.start_time.isoformat(),
                            "end_time": event.end_time.isoformat(),
                            "location": event.location,
                            "is_recurring": False
                        })
            
            # Sort expanded events by start time
            expanded_events.sort(key=lambda x: x["start_time"])
            
            # Apply pagination to expanded events
            paginated_expanded = expanded_events[(page - 1) * limit:page * limit]
            
            return jsonify({
                "events": paginated_expanded,
                "total": len(expanded_events),
                "page": page,
                "limit": limit,
                "pages": (len(expanded_events) + limit - 1) // limit
            }), 200
        
        return jsonify({
            "events": events_list,
            "total": total,
            "page": page,
            "limit": limit,
            "pages": (total + limit - 1) // limit
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get Event by ID
@app.route('/api/events/<event_id>', methods=['GET'])
@jwt_required()
def get_event(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has access to this event
        has_access = False
        user_role = None
        
        # Check if user is the creator
        if str(event.created_by.id) == user_id:
            has_access = True
            user_role = "owner"
        
        # Check if user has permissions
        if not has_access:
            for permission in event.permissions:
                if str(permission.user.id) == user_id:
                    has_access = True
                    user_role = permission.role
                    break
        
        if not has_access:
            return jsonify({"message": "Access denied"}), 403
            
        # Format permissions for response
        permissions_list = []
        for permission in event.permissions:
            permissions_list.append({
                "user_id": str(permission.user.id),
                "username": permission.user.username,
                "role": permission.role
            })
            
        # Format and return the event
        event_data = {
            "id": str(event.id),
            "title": event.title,
            "description": event.description,
            "start_time": event.start_time.isoformat(),
            "end_time": event.end_time.isoformat(),
            "location": event.location,
            "is_recurring": event.is_recurring,
            "created_by": {
                "id": str(event.created_by.id),
                "username": event.created_by.username
            },
            "user_role": user_role,
            "permissions": permissions_list,
            "created_at": event.created_at.isoformat()
        }
        
        # Add recurrence pattern if applicable
        if event.is_recurring and event.recurrence_pattern:
            pattern = event.recurrence_pattern
            recurrence_data = {
                "frequency": pattern.frequency,
                "interval": pattern.interval
            }
            
            if pattern.days_of_week:
                recurrence_data["days_of_week"] = pattern.days_of_week
                
            if pattern.day_of_month:
                recurrence_data["day_of_month"] = pattern.day_of_month
                
            if pattern.end_date:
                recurrence_data["end_date"] = pattern.end_date.isoformat()
                
            if pattern.count:
                recurrence_data["count"] = pattern.count
                
            event_data["recurrence_pattern"] = recurrence_data
        
        return jsonify(event_data), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update Event by ID - FIXED VERSION
@app.route('/api/events/<event_id>', methods=['PUT'])
@jwt_required()
def update_event(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has edit permissions
        has_permission = False
        
        # Check if user is the creator
        if str(event.created_by.id) == user_id:
            has_permission = True
        
        # Check if user has editor role
        if not has_permission:
            for permission in event.permissions:
                if str(permission.user.id) == user_id and permission.role in ["owner", "editor"]:
                    has_permission = True
                    break
        
        if not has_permission:
            return jsonify({"message": "You don't have permission to update this event"}), 403
        
        # Create a snapshot of the current state BEFORE making changes
        pre_update_snapshot = event.create_snapshot()
            
        # Get the update data
        data = request.json
        updates = {}
        changes = {}  # Track changes for history
        
        # Process updates
        if 'title' in data and data['title'] != event.title:
            updates['title'] = data['title']
            changes['title'] = {'old': event.title, 'new': data['title']}
            
        if 'description' in data and data['description'] != event.description:
            updates['description'] = data['description']
            changes['description'] = {'old': event.description, 'new': data['description']}
            
        if 'location' in data and data['location'] != event.location:
            updates['location'] = data['location']
            changes['location'] = {'old': event.location, 'new': data['location']}
            
        # Process datetime updates
        if 'start_time' in data or 'end_time' in data:
            start_time = event.start_time
            end_time = event.end_time
            
            if 'start_time' in data:
                try:
                    start_time = datetime.datetime.fromisoformat(data['start_time'])
                    changes['start_time'] = {'old': event.start_time.isoformat(), 'new': data['start_time']}
                except ValueError:
                    return jsonify({"message": "Invalid start_time format"}), 400
                    
            if 'end_time' in data:
                try:
                    end_time = datetime.datetime.fromisoformat(data['end_time'])
                    changes['end_time'] = {'old': event.end_time.isoformat(), 'new': data['end_time']}
                except ValueError:
                    return jsonify({"message": "Invalid end_time format"}), 400
                    
            # Validate time range
            if end_time <= start_time:
                return jsonify({"message": "End time must be after start time"}), 400
                
            # Check for conflicts
            conflicting_events = detect_event_conflicts(user_id, start_time, end_time, exclude_event_id=event_id)
            if conflicting_events:
                conflict_details = [{"id": str(e.id), "title": e.title, "start_time": e.start_time, "end_time": e.end_time} for e in conflicting_events]
                return jsonify({
                    "message": "Event conflicts with existing events",
                    "conflicts": conflict_details
                }), 409
                
            if 'start_time' in data:
                updates['start_time'] = start_time
                
            if 'end_time' in data:
                updates['end_time'] = end_time
        
        # Process recurrence pattern updates
        if 'is_recurring' in data:
            updates['is_recurring'] = data['is_recurring']
            changes['is_recurring'] = {'old': event.is_recurring, 'new': data['is_recurring']}
            
            if data['is_recurring'] and 'recurrence_pattern' in data:
                pattern_data = data['recurrence_pattern']
                
                # Validate recurrence pattern
                if 'frequency' not in pattern_data:
                    return jsonify({"message": "Frequency is required in recurrence pattern"}), 400
                    
                # Convert end_date to datetime if present
                if 'end_date' in pattern_data:
                    try:
                        pattern_data['end_date'] = datetime.datetime.fromisoformat(pattern_data['end_date'])
                    except ValueError:
                        return jsonify({"message": "Invalid end_date format in recurrence pattern"}), 400
                
                # Create a new recurrence pattern
                updates['recurrence_pattern'] = RecurrencePattern(**pattern_data)
                changes['recurrence_pattern'] = {'updated': True}
        
        # If there are no updates, return success without changes
        if not updates:
            return jsonify({"message": "No changes detected"}), 200
            
        # Record change history with snapshot
        user = User.objects(id=ObjectId(user_id)).first()
        history_entry = EventHistory(
            modified_by=user,
            modified_at=datetime.datetime.utcnow(),
            changes=changes,
            event_snapshot=pre_update_snapshot  # Store the state before changes
        )
        
        # Update the event
        event.update(push__history=history_entry, **updates)
        
        return jsonify({
            "message": "Event updated successfully",
            "changes": changes,
            "version_id": history_entry.version_id  # Return the version ID for reference
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Delete Event by ID
@app.route('/api/events/<event_id>', methods=['DELETE'])
@jwt_required()
def delete_event(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has permission to delete
        has_permission = False
        
        # Check if user is the creator
        if str(event.created_by.id) == user_id:
            has_permission = True
        
        # Check if user has owner role
        if not has_permission:
            for permission in event.permissions:
                if str(permission.user.id) == user_id and permission.role == "owner":
                    has_permission = True
                    break
        
        if not has_permission:
            return jsonify({"message": "You don't have permission to delete this event"}), 403
            
        # Delete the event
        event.delete()
        
        return jsonify({"message": "Event deleted successfully"}), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Batch Create Events
@app.route('/api/events/batch', methods=['POST'])
@jwt_required()
def batch_create_events():
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        user = User.objects(id=ObjectId(user_id)).first()
        
        if not user:
            return jsonify({"message": "User not found"}), 404
            
        # Get the batch of events
        data = request.json
        
        if not isinstance(data, list):
            return jsonify({"message": "Request body must be an array of events"}), 400
            
        if len(data) == 0:
            return jsonify({"message": "No events provided"}), 400
            
        # Validate all events before creating any
        for i, event_data in enumerate(data):
            # Check required fields
            required_fields = ['title', 'description', 'start_time', 'end_time']
            for field in required_fields:
                if field not in event_data:
                    return jsonify({"message": f"Event at index {i} is missing required field: {field}"}), 400
                    
            # Validate datetime formats
            try:
                start_time = datetime.datetime.fromisoformat(event_data['start_time'])
                end_time = datetime.datetime.fromisoformat(event_data['end_time'])
            except ValueError:
                return jsonify({"message": f"Event at index {i} has invalid datetime format"}), 400
                
            # Check if end time is after start time
            if end_time <= start_time:
                return jsonify({"message": f"Event at index {i} has end time before start time"}), 400
                
            # Validate recurrence pattern if present
            if event_data.get('is_recurring', False) and 'recurrence_pattern' not in event_data:
                return jsonify({"message": f"Event at index {i} is recurring but missing recurrence pattern"}), 400
                
            if 'recurrence_pattern' in event_data:
                pattern = event_data['recurrence_pattern']
                if 'frequency' not in pattern:
                    return jsonify({"message": f"Event at index {i} has recurrence pattern missing frequency"}), 400
        
        # Check for conflicts across all events
        all_conflicts = []
        for i, event_data in enumerate(data):
            start_time = datetime.datetime.fromisoformat(event_data['start_time'])
            end_time = datetime.datetime.fromisoformat(event_data['end_time'])
            
            conflicts = detect_event_conflicts(user_id, start_time, end_time)
            if conflicts:
                conflict_details = [{"id": str(e.id), "title": e.title, "start_time": e.start_time, "end_time": e.end_time} for e in conflicts]
                all_conflicts.append({
                    "event_index": i,
                    "conflicts": conflict_details
                })
        
        # If there are conflicts, return them all at once
        if all_conflicts:
            return jsonify({
                "message": "Some events conflict with existing events",
                "conflicts": all_conflicts
            }), 409
            
        # Create all events
        created_events = []
        for event_data in data:
            start_time = datetime.datetime.fromisoformat(event_data['start_time'])
            end_time = datetime.datetime.fromisoformat(event_data['end_time'])
            
            # Create recurrence pattern if applicable
            recurrence_pattern = None
            if event_data.get('is_recurring', False) and 'recurrence_pattern' in event_data:
                pattern_data = event_data['recurrence_pattern']
                
                # Convert end_date to datetime if present
                if 'end_date' in pattern_data:
                    pattern_data['end_date'] = datetime.datetime.fromisoformat(pattern_data['end_date'])
                
                recurrence_pattern = RecurrencePattern(**pattern_data)
            
            # Create the event
            event = Event(
                title=event_data['title'],
                description=event_data['description'],
                start_time=start_time,
                end_time=end_time,
                location=event_data.get('location', ''),
                created_by=user,
                is_recurring=event_data.get('is_recurring', False),
                recurrence_pattern=recurrence_pattern,
                permissions=[]  # Initial permissions (owner only)
            )
            
            event.save()
            
            created_events.append({
                "id": str(event.id),
                "title": event.title
            })
        
        return jsonify({
            "message": f"Successfully created {len(created_events)} events",
            "events": created_events
        }), 201
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Share event - FIXED VERSION (to include snapshot)
@app.route('/api/events/<event_id>/share', methods=['POST'])
@jwt_required()
def share_event(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has permission to share
        # Only owners can share events
        if not event.user_has_role(user_id, ["owner"]):
            return jsonify({"message": "You don't have permission to share this event"}), 403
            
        # Get the share data
        data = request.json
        if not data or not isinstance(data, dict):
            return jsonify({"message": "Invalid request data"}), 400
            
        # Validate required fields
        if 'user_id' not in data or 'role' not in data:
            return jsonify({"message": "user_id and role are required"}), 400
            
        # Validate role
        if data['role'] not in ["owner", "editor", "viewer"]:
            return jsonify({"message": "Invalid role. Must be owner, editor, or viewer"}), 400
            
        # Find the user to share with
        target_user = User.objects(id=ObjectId(data['user_id'])).first()
        if not target_user:
            return jsonify({"message": "User not found"}), 404
            
        # Check if the event is already shared with this user
        for permission in event.permissions:
            if str(permission.user.id) == data['user_id']:
                return jsonify({"message": "Event is already shared with this user"}), 400
                
        # Create a snapshot before sharing
        pre_share_snapshot = event.create_snapshot()
                
        # Create a new permission
        new_permission = EventPermission(
            user=target_user,
            role=data['role']
        )
        
        # Add the permission to the event
        event.update(push__permissions=new_permission)
        
        # Create a history entry
        user = User.objects(id=ObjectId(user_id)).first()
        history_entry = EventHistory(
            modified_by=user,
            modified_at=datetime.datetime.utcnow(),
            changes={
                "action": "share",
                "target_user": str(target_user.id),
                "target_username": target_user.username,
                "role": data['role']
            },
            event_snapshot=pre_share_snapshot
        )
        event.update(push__history=history_entry)
        
        # Send notification
        send_notification(target_user.id, f"Event '{event.title}' has been shared with you", "event_shared", {
            "event_id": str(event.id),
            "shared_by": str(user_id)
        })
        
        return jsonify({
            "message": "Event shared successfully",
            "version_id": history_entry.version_id,
            "permission": {
                "user_id": str(target_user.id),
                "username": target_user.username,
                "role": data['role']
            }
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# List all permissions for an event
@app.route('/api/events/<event_id>/permissions', methods=['GET'])
@jwt_required()
def list_permissions(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has access to this event
        if not event.user_has_role(user_id, ["owner", "editor", "viewer"]):
            return jsonify({"message": "Access denied"}), 403
            
        # Format and return permissions
        permissions = []
        
        # Add the creator as owner
        permissions.append({
            "user_id": str(event.created_by.id),
            "username": event.created_by.username,
            "role": "owner",
            "is_creator": True
        })
        
        # Add other permissions
        for permission in event.permissions:
            permissions.append({
                "user_id": str(permission.user.id),
                "username": permission.user.username,
                "role": permission.role,
                "is_creator": False
            })
            
        return jsonify({
            "event_id": str(event.id),
            "title": event.title,
            "permissions": permissions
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Update permissions for a user
@app.route('/api/events/<event_id>/permissions/<user_id>', methods=['PUT'])
@jwt_required()
def update_permission(event_id, user_id):
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if current user has permission to update permissions
        if not event.user_has_role(current_user_id, ["owner"]):
            return jsonify({"message": "You don't have permission to update permissions"}), 403
            
        # Get the update data
        data = request.json
        if not data or not isinstance(data, dict) or 'role' not in data:
            return jsonify({"message": "Role is required"}), 400
            
        # Validate role
        if data['role'] not in ["owner", "editor", "viewer"]:
            return jsonify({"message": "Invalid role. Must be owner, editor, or viewer"}), 400
            
        # Check if trying to modify the creator
        if str(event.created_by.id) == user_id:
            return jsonify({"message": "Cannot modify permissions for the event creator"}), 400
            
        # Find the permission to update
        permission_found = False
        old_role = None
        
        for i, permission in enumerate(event.permissions):
            if str(permission.user.id) == user_id:
                permission_found = True
                old_role = permission.role
                
                # Update the role
                event.permissions[i].role = data['role']
                break
                
        if not permission_found:
            return jsonify({"message": "User does not have permission for this event"}), 404
            
        # Save the updated permissions
        event.save()
        
        # Record the change in history
        user = User.objects(id=ObjectId(current_user_id)).first()
        history_entry = EventHistory(
            modified_by=user,
            modified_at=datetime.datetime.utcnow(),
            changes={
                "action": "update_permission",
                "target_user": user_id,
                "old_role": old_role,
                "new_role": data['role']
            }
        )
        event.update(push__history=history_entry)
        
        # Send notification
        send_notification(user_id, f"Your permission for event '{event.title}' has changed", "permission_changed", {
            "event_id": str(event.id),
            "old_role": old_role,
            "new_role": data['role']
        })
        
        return jsonify({
            "message": "Permission updated successfully",
            "user_id": user_id,
            "role": data['role']
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Remove access for a user
@app.route('/api/events/<event_id>/permissions/<user_id>', methods=['DELETE'])
@jwt_required()
def remove_permission(event_id, user_id):
    try:
        current_user = get_jwt_identity()
        current_user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if current user has permission to update permissions
        if not event.user_has_role(current_user_id, ["owner"]):
            return jsonify({"message": "You don't have permission to remove access"}), 403
            
        # Check if trying to remove the creator
        if str(event.created_by.id) == user_id:
            return jsonify({"message": "Cannot remove the event creator"}), 400
            
        # Find the permission to remove
        permission_found = False
        removed_role = None
        
        for permission in event.permissions:
            if str(permission.user.id) == user_id:
                permission_found = True
                removed_role = permission.role
                break
                
        if not permission_found:
            return jsonify({"message": "User does not have permission for this event"}), 404
            
        # Remove the permission
        Event.objects(id=ObjectId(event_id)).update_one(
            pull__permissions__user=ObjectId(user_id)
        )
        
        # Record the change in history
        user = User.objects(id=ObjectId(current_user_id)).first()
        history_entry = EventHistory(
            modified_by=user,
            modified_at=datetime.datetime.utcnow(),
            changes={
                "action": "remove_permission",
                "target_user": user_id,
                "removed_role": removed_role
            }
        )
        event.update(push__history=history_entry)
        
        # Send notification
        send_notification(user_id, f"Your access to event '{event.title}' has been removed", "permission_removed", {
            "event_id": str(event.id)
        })
        
        return jsonify({
            "message": "Permission removed successfully"
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Rollback Event to Previous Version - FIXED VERSION
@app.route('/api/events/<event_id>/rollback/<version_id>', methods=['POST'])
@jwt_required()
def rollback_event(event_id, version_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has permission to rollback (owner or editor)
        if not event.user_has_role(user_id, ["owner", "editor"]):
            return jsonify({"message": "You don't have permission to rollback this event"}), 403
        
        # Handle special cases for version_id
        target_snapshot = None
        target_version_info = None
        
        if version_id == "creation":
            # Rollback to the original creation state
            # We need to reconstruct the original state from the first snapshot or creation data
            if event.history:
                # Get the earliest snapshot
                earliest_entry = min(event.history, key=lambda x: x.modified_at)
                target_snapshot = earliest_entry.event_snapshot
                target_version_info = {
                    "version_id": "creation",
                    "modified_at": event.created_at,
                    "modified_by": event.created_by
                }
            else:
                return jsonify({"message": "No history available for rollback"}), 400
        else:
            # Find the version to rollback to by version_id
            target_history_entry = None
            for history_entry in event.history:
                if history_entry.version_id == version_id:
                    target_history_entry = history_entry
                    break
                    
            if not target_history_entry:
                return jsonify({"message": f"Version {version_id} not found"}), 404
                
            target_snapshot = target_history_entry.event_snapshot
            target_version_info = {
                "version_id": target_history_entry.version_id,
                "modified_at": target_history_entry.modified_at,
                "modified_by": target_history_entry.modified_by
            }
        
        if not target_snapshot:
            return jsonify({"message": "No snapshot available for this version"}), 400
            
        # Prepare rollback updates
        updates = {}
        rollback_changes = {}
        
        # Get current state for comparison
        current_snapshot = event.create_snapshot()
        
        # Compare and prepare updates
        for field, target_value in target_snapshot.items():
            current_value = current_snapshot.get(field)
            
            if field in ['start_time', 'end_time']:
                if target_value and current_value != target_value:
                    try:
                        target_datetime = datetime.datetime.fromisoformat(target_value)
                        updates[field] = target_datetime
                        rollback_changes[field] = {
                            'old': current_value,
                            'new': target_value
                        }
                    except ValueError:
                        continue
            elif field == 'recurrence_pattern':
                # Handle recurrence pattern rollback
                if target_value != current_value:
                    if target_value:
                        # Reconstruct recurrence pattern
                        pattern_data = target_value.copy()
                        if pattern_data.get('end_date'):
                            pattern_data['end_date'] = datetime.datetime.fromisoformat(pattern_data['end_date'])
                        updates['recurrence_pattern'] = RecurrencePattern(**pattern_data)
                    else:
                        updates['recurrence_pattern'] = None
                    
                    rollback_changes['recurrence_pattern'] = {
                        'old': 'current pattern',
                        'new': 'rolled back pattern'
                    }
            elif current_value != target_value:
                updates[field] = target_value
                rollback_changes[field] = {
                    'old': current_value,
                    'new': target_value
                }
        
        # Validate the rollback state if time fields are being changed
        if 'start_time' in updates or 'end_time' in updates:
            rollback_start = updates.get('start_time', event.start_time)
            rollback_end = updates.get('end_time', event.end_time)
            
            if rollback_end <= rollback_start:
                return jsonify({"message": "Cannot rollback: would result in invalid time range"}), 400
                
            # Check for conflicts with the rollback state
            conflicts = detect_event_conflicts(
                user_id, 
                rollback_start, 
                rollback_end, 
                exclude_event_id=event_id
            )
            
            if conflicts:
                conflict_details = [{"id": str(e.id), "title": e.title, "start_time": e.start_time, "end_time": e.end_time} for e in conflicts]
                return jsonify({
                    "message": "Cannot rollback: would conflict with existing events",
                    "conflicts": conflict_details
                }), 409
        
        # Create a snapshot of the current state before rollback
        pre_rollback_snapshot = event.create_snapshot()
        
        # Create a history entry for the rollback
        user = User.objects(id=ObjectId(user_id)).first()
        rollback_history = EventHistory(
            modified_by=user,
            modified_at=datetime.datetime.utcnow(),
            changes={
                "action": "rollback",
                "target_version_id": version_id,
                "rolled_back_to": target_version_info["modified_at"].isoformat(),
                **rollback_changes
            },
            event_snapshot=pre_rollback_snapshot  # Store state before rollback
        )
        
        # Apply the rollback
        if updates:
            event.update(push__history=rollback_history, **updates)
        else:
            event.update(push__history=rollback_history)
            
        return jsonify({
            "message": "Event rolled back successfully",
            "rolled_back_to": target_version_info["modified_at"].isoformat(),
            "target_version_id": version_id,
            "rollback_version_id": rollback_history.version_id,
            "changes": rollback_changes
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get event edit history - FIXED VERSION
@app.route('/api/events/<event_id>/history', methods=['GET'])
@jwt_required()
def get_event_history(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has access to this event
        if not event.user_has_role(user_id, ["owner", "editor", "viewer"]):
            return jsonify({"message": "Access denied"}), 403
            
        # Format and return history
        history = []
        
        # Add creation entry
        history.append({
            "version_id": "creation",
            "action": "creation",
            "modified_by": {
                "id": str(event.created_by.id),
                "username": event.created_by.username
            },
            "modified_at": event.created_at.isoformat(),
            "changes": {"action": "create"},
            "summary": "Event created"
        })
        
        # Add history entries
        for entry in event.history:
            history.append({
                "version_id": entry.version_id,  # Now using consistent string ID
                "action": entry.changes.get('action', 'update'),
                "modified_by": {
                    "id": str(entry.modified_by.id),
                    "username": entry.modified_by.username
                },
                "modified_at": entry.modified_at.isoformat(),
                "changes": entry.changes,
                "summary": generate_change_summary(entry.changes)
            })
            
        # Sort by modification date, newest first
        history.sort(key=lambda x: x["modified_at"], reverse=True)
        
        return jsonify({
            "event_id": str(event.id),
            "title": event.title,
            "history": history
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Get Event Changelog
@app.route('/api/events/<event_id>/changelog', methods=['GET'])
@jwt_required()
def get_event_changelog(event_id):
    try:
        current_user = get_jwt_identity()
        user_id = current_user.get('user_id')
        
        # Find the event
        event = Event.objects(id=ObjectId(event_id)).first()
        if not event:
            return jsonify({"message": "Event not found"}), 404
            
        # Check if user has access to this event
        if not event.user_has_role(user_id, ["owner", "editor", "viewer"]):
            return jsonify({"message": "Access denied"}), 403
            
        # Format and return history
        history = []
        
        # Add creation entry
        history.append({
            "version_id": "creation",
            "action": "creation",
            "modified_by": {
                "id": str(event.created_by.id),
                "username": event.created_by.username
            },
            "modified_at": event.created_at.isoformat(),
            "changes": {"action": "create"},
            "summary": "Event created"
        })
        
        # Add history entries
        for entry in event.history:
            history.append({
                "version_id": entry.version_id,  # Now using consistent string ID
                "action": entry.changes.get('action', 'update'),
                "modified_by": {
                    "id": str(entry.modified_by.id),
                    "username": entry.modified_by.username
                },
                "modified_at": entry.modified_at.isoformat(),
                "changes": entry.changes,
                "summary": generate_change_summary(entry.changes)
            })
            
        # Sort by modification date, newest first
        history.sort(key=lambda x: x["modified_at"], reverse=True)
        
        return jsonify({
            "event_id": str(event.id),
            "title": event.title,
            "history": history
        }), 200
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Get Diff Between Two Versions
# @app.route('/api/events/<event_id>/diff/<version_id1>/<version_id2>', methods=['GET'])
# @jwt_required()
# def get_event_diff(event_id, version_id1, version_id2):
#     try:
#         current_user = get_jwt_identity()
#         user_id = current_user.get('user_id')
#         
#         # Find the event
#         event = Event.objects(id=ObjectId(event_id)).first()
#         if not event:
#             return jsonify({"message": "Event not found"}), 404
#             
#         # Check if user has access
#         if not event.user_has_role(user_id, ["owner", "editor", "viewer"]):
#             return jsonify({"message": "Access denied"}), 403
#             
#         # Helper to build a full “current” or “creation” version
#         def make_snapshot(version_id, timestamp):
#             return {
#                 "id": version_id,
#                 "modified_at": timestamp,
#                 "state": {
#                     "title":        event.title,
#                     "description":  event.description,
#                     "start_time":   event.start_time,
#                     "end_time":     event.end_time,
#                     "location":     event.location,
#                     "is_recurring": event.is_recurring
#                 }
#             }
#         
#         # Load version1
#         if version_id1 == "current":
#             version1 = make_snapshot("current", datetime.utcnow())
#         elif version_id1 == "creation":
#             version1 = make_snapshot("creation", event.created_at)
#         else:
#             version1 = next(
#                 ({
#                     "id":         entry.version_id,
#                     "modified_at": entry.modified_at,
#                     "modified_by": entry.modified_by,
#                     "changes":     entry.changes
#                 } for entry in event.history
#                   if entry.version_id == version_id1),
#                 None
#             )
#         
#         # Load version2 (same pattern)
#         if version_id2 == "current":
#             version2 = make_snapshot("current", datetime.utcnow())
#         elif version_id2 == "creation":
#             version2 = make_snapshot("creation", event.created_at)
#         else:
#             version2 = next(
#                 ({
#                     "id":         entry.version_id,
#                     "modified_at": entry.modified_at,
#                     "modified_by": entry.modified_by,
#                     "changes":     entry.changes
#                 } for entry in event.history
#                   if entry.version_id == version_id2),
#                 None
#             )
#         
#         if not version1:
#             return jsonify({"message": f"Version {version_id1} not found"}), 404
#         if not version2:
#             return jsonify({"message": f"Version {version_id2} not found"}), 404
#         
#         # Reconstruct and diff
#         state1 = reconstruct_event_state(event, version1)
#         state2 = reconstruct_event_state(event, version2)
#         diff   = generate_event_diff(state1, state2)
#         
#         # Build response
#         def fmt_version(v):
#             return {
#                 "id":         v["id"],
#                 "modified_at": v["modified_at"].isoformat(),
#                 "modified_by": v.get("modified_by", {
#                     "id":       str(event.created_by.id),
#                     "username": event.created_by.username
#                 })
#             }
#         
#         return jsonify({
#             "event_id": str(event.id),
#             "title":    event.title,
#             "version1": fmt_version(version1),
#             "version2": fmt_version(version2),
#             "diff":     diff
#         }), 200

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
