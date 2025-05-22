from functools import wraps
from flask import request, jsonify
from flask_jwt_extended import get_jwt_identity, verify_jwt_in_request
from bson import ObjectId
import datetime

# Decorator for verifying roles
def role_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            claims = get_jwt_identity()
            if claims.get("role") == role:
                return fn(*args, **kwargs)
            else:
                return jsonify({"message": "Insufficient permissions"}), 403
        return decorator
    return wrapper

# Decorator for event permission verification
def event_permission_required(roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            from models import Event
            verify_jwt_in_request()
            claims = get_jwt_identity()
            user_id = claims.get("user_id")
            
            # Get event_id from the URL parameters
            event_id = kwargs.get("event_id")
            if not event_id:
                return jsonify({"message": "Event ID is required"}), 400
                
            # Find the event
            event = Event.objects(id=ObjectId(event_id)).first()
            if not event:
                return jsonify({"message": "Event not found"}), 404
                
            # Check if the user has the required role
            if event.user_has_role(user_id, roles):
                # Add the event to the kwargs so the route function can access it
                kwargs["event"] = event
                return fn(*args, **kwargs)
            else:
                return jsonify({"message": "Insufficient permissions for this event"}), 403
        return decorator
    return wrapper

# Function to detect time conflicts for events
def detect_event_conflicts(user_id, start_time, end_time, exclude_event_id=None):
    from models import Event, EventPermission
    
    # Find events where the user participates (either created by user or has permission)
    # that overlap with the given time range
    
    # An event conflicts if:
    # 1. It starts during the new event's time range, or
    # 2. It ends during the new event's time range, or
    # 3. It completely encompasses the new event's time range
    
    query = {
        "$or": [
            # Events created by the user
            {"created_by": ObjectId(user_id)},
            # Events where the user has permissions
            {"permissions.user": ObjectId(user_id)}
        ],
        "$and": [
            {"start_time": {"$lt": end_time}},
            {"end_time": {"$gt": start_time}}
        ]
    }
    
    # Exclude the current event if updating
    if exclude_event_id:
        query["id"] = {"$ne": ObjectId(exclude_event_id)}
    
    conflicting_events = Event.objects(__raw__=query)
    return list(conflicting_events)

# Function to expand recurring events
def expand_recurring_events(event, start_date, end_date):
    # This function would generate all instances of a recurring event
    # within the specified date range based on the recurrence pattern
    
    # This is a simplified implementation - a production system would need
    # more sophisticated recurrence rule handling
    
    if not event.is_recurring or not event.recurrence_pattern:
        return [event]
        
    expanded_events = []
    current_date = event.start_time
    pattern = event.recurrence_pattern
    
    # Calculate event duration in seconds for consistency when creating new events
    duration = (event.end_time - event.start_time).total_seconds()
    
    # Set the end boundary for recurrence
    recurrence_end = pattern.end_date if pattern.end_date else end_date
    
    # Generate recurring events
    while current_date <= recurrence_end and current_date <= end_date:
        if current_date >= start_date:
            # Create a new instance of the event at this date
            event_instance = {
                "id": str(event.id),
                "title": event.title,
                "description": event.description,
                "start_time": current_date,
                "end_time": current_date + datetime.timedelta(seconds=duration),
                "location": event.location,
                "is_recurring": True,
                "recurrence_parent_id": str(event.id)
            }
            expanded_events.append(event_instance)
        
        # Move to the next occurrence based on frequency
        if pattern.frequency == "daily":
            current_date += datetime.timedelta(days=int(pattern.interval))
        elif pattern.frequency == "weekly":
            current_date += datetime.timedelta(weeks=int(pattern.interval))
        elif pattern.frequency == "monthly":
            # Simplified monthly recurrence (add months)
            new_month = current_date.month + int(pattern.interval)
            new_year = current_date.year + (new_month - 1) // 12
            new_month = ((new_month - 1) % 12) + 1
            # Try to maintain the same day, but adjust for months with fewer days
            try:
                current_date = current_date.replace(year=new_year, month=new_month)
            except ValueError:
                # If the day doesn't exist in the month (e.g., Feb 30), use the last day
                if new_month == 2:
                    last_day = 29 if new_year % 4 == 0 and (new_year % 100 != 0 or new_year % 400 == 0) else 28
                elif new_month in [4, 6, 9, 11]:
                    last_day = 30
                else:
                    last_day = 31
                current_date = current_date.replace(year=new_year, month=new_month, day=last_day)
        elif pattern.frequency == "yearly":
            current_date = current_date.replace(year=current_date.year + int(pattern.interval))
            
    return expanded_events

# Helper function to generate change summary
def generate_change_summary(changes):
    """Generate a human-readable summary of changes"""
    if not changes:
        return "No changes"
        
    action = changes.get('action', 'update')
    
    if action == 'create':
        return "Event created"
    elif action == 'share':
        return f"Event shared with user (role: {changes.get('role', 'unknown')})"
    elif action == 'update_permission':
        return f"Permission updated from {changes.get('old_role')} to {changes.get('new_role')}"
    elif action == 'remove_permission':
        return f"Permission removed (was {changes.get('removed_role')})"
    elif action == 'rollback':
        return f"Rolled back to version from {changes.get('rolled_back_to')}"
    else:
        # Generate summary for field updates
        updated_fields = []
        for field, change_data in changes.items():
            if isinstance(change_data, dict) and 'old' in change_data and 'new' in change_data:
                updated_fields.append(field.replace('_', ' ').title())
                
        if updated_fields:
            return f"Updated: {', '.join(updated_fields)}"
        else:
            return "Event updated"

# Helper function to reconstruct event state at a specific version
def reconstruct_event_state(event, version):
    """Reconstruct the event state at a specific version"""
    if version["id"] == "current":
        return version["state"]
    elif version["id"] == "creation":
        return version["state"]
    else:
        # This is a simplified reconstruction
        # In a production system, you'd want to store complete snapshots or implement proper state reconstruction
        current_state = {
            "title": event.title,
            "description": event.description,
            "start_time": event.start_time,
            "end_time": event.end_time,
            "location": event.location,
            "is_recurring": event.is_recurring
        }
        
        # Apply changes in reverse until we reach the target version
        for entry in reversed(event.history):
            if entry.modified_at <= version["modified_at"]:
                break
                
            # Reverse the changes
            changes = entry.changes
            for field, change_data in changes.items():
                if isinstance(change_data, dict) and 'old' in change_data:
                    if field in ['start_time', 'end_time']:
                        current_state[field] = datetime.fromisoformat(change_data['old'])
                    elif field in current_state:
                        current_state[field] = change_data['old']
                        
        return current_state

# Helper function to generate diff between two states
def generate_event_diff(state1, state2):
    """Generate a detailed diff between two event states"""
    diff = {
        "changed_fields": [],
        "unchanged_fields": [],
        "field_changes": {}
    }
    
    # Compare all fields
    all_fields = set(state1.keys()) | set(state2.keys())
    
    for field in all_fields:
        value1 = state1.get(field)
        value2 = state2.get(field)
        
        # Convert datetime objects to strings for comparison
        if isinstance(value1, datetime):
            value1 = value1.isoformat()
        if isinstance(value2, datetime):
            value2 = value2.isoformat()
            
        if value1 != value2:
            diff["changed_fields"].append(field)
            diff["field_changes"][field] = {
                "version1_value": value1,
                "version2_value": value2,
                "change_type": determine_change_type(value1, value2)
            }
        else:
            diff["unchanged_fields"].append(field)
            
    return diff

# Helper function to determine change type
def determine_change_type(value1, value2):
    """Determine the type of change between two values"""
    if value1 is None and value2 is not None:
        return "added"
    elif value1 is not None and value2 is None:
        return "removed"
    elif value1 != value2:
        return "modified"
    else:
        return "unchanged"
