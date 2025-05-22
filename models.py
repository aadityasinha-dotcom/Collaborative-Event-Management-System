from mongoengine import Document, StringField, DateTimeField, BooleanField, ListField, ReferenceField, DictField, EmbeddedDocument, EmbeddedDocumentField, ObjectIdField
from bson import ObjectId
import datetime
import uuid

# User Model
class User(Document):
    username = StringField(required=True, unique=True)
    email = StringField(required=True, unique=True)
    password = StringField(required=True)
    role = StringField(required=True, choices=["owner", "editor", "viewer"])

# Project Model
class Project(Document):
    name = StringField(required=True)
    description = StringField(required=True)

# Recurrence Pattern Model
class RecurrencePattern(EmbeddedDocument):
    frequency = StringField(required=True, choices=["daily", "weekly", "monthly", "yearly"])
    interval = StringField(default=1)  # Every X days/weeks/months/years
    days_of_week = ListField(StringField(), default=[])  # For weekly recurrence
    day_of_month = StringField()  # For monthly recurrence
    end_date = DateTimeField()  # When the recurrence ends
    count = StringField()  # Number of occurrences

# EventPermission Model (for collaboration)
class EventPermission(EmbeddedDocument):
    user = ReferenceField(User, required=True)
    role = StringField(required=True, choices=["owner", "editor", "viewer"])

# Event History (for tracking changes) - FIXED VERSION
class EventHistory(EmbeddedDocument):
    # Use a string ID instead of ObjectId to ensure consistency
    version_id = StringField(required=True, default=lambda: str(uuid.uuid4()))
    modified_by = ReferenceField(User)
    modified_at = DateTimeField(default=datetime.datetime.utcnow)
    changes = DictField()  # Store field changes
    # Store a snapshot of the event state at this point for easier rollback
    event_snapshot = DictField()

# Event Model
class Event(Document):
    title = StringField(required=True)
    description = StringField(required=True)
    start_time = DateTimeField(required=True)
    end_time = DateTimeField(required=True)
    location = StringField()
    created_by = ReferenceField(User, required=True)
    created_at = DateTimeField(default=datetime.datetime.utcnow)
    is_recurring = BooleanField(default=False)
    recurrence_pattern = EmbeddedDocumentField(RecurrencePattern)
    permissions = ListField(EmbeddedDocumentField(EventPermission))
    history = ListField(EmbeddedDocumentField(EventHistory))
    
    # Helper method to check if a user has a specific role for this event
    def user_has_role(self, user_id, roles):
        if not isinstance(roles, list):
            roles = [roles]
            
        # If the user is the creator, they have owner privileges
        if str(self.created_by.id) == str(user_id):
            return True
            
        # Check the permissions list
        for permission in self.permissions:
            if str(permission.user.id) == str(user_id) and permission.role in roles:
                return True
                
        return False
    
    # Helper method to create a snapshot of current state
    def create_snapshot(self):
        return {
            "title": self.title,
            "description": self.description,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "location": self.location,
            "is_recurring": self.is_recurring,
            "recurrence_pattern": self._serialize_recurrence_pattern()
        }
    
    def _serialize_recurrence_pattern(self):
        if not self.recurrence_pattern:
            return None
        return {
            "frequency": self.recurrence_pattern.frequency,
            "interval": self.recurrence_pattern.interval,
            "days_of_week": self.recurrence_pattern.days_of_week,
            "day_of_month": self.recurrence_pattern.day_of_month,
            "end_date": self.recurrence_pattern.end_date.isoformat() if self.recurrence_pattern.end_date else None,
            "count": self.recurrence_pattern.count
        }

# Notification Model
class Notification(Document):
    user = ReferenceField(User, required=True)
    message = StringField(required=True)
    created_at = DateTimeField(default=datetime.datetime.utcnow)
    read = BooleanField(default=False)
    notification_type = StringField(required=True)  # event_shared, event_updated, permission_changed, etc.
    data = DictField()  # Additional data related to the notification
