from flask_sqlalchemy import SQLAlchemy
import os

LOCAL_RUN = True

if LOCAL_RUN:
    from flask import Flask

    app = Flask(__name__)
    # Default to instance directory relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    instance_dir = os.path.join(script_dir, '..', 'instance')

    # Create instance directory if it doesn't exist
    if not os.path.exists(instance_dir):
        os.makedirs(instance_dir)

    default_db_path = os.path.join(instance_dir, 'cmd_tlm.sqlite')
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{default_db_path}'
    db = SQLAlchemy(app)
else:
    db = SQLAlchemy()

class Command(db.Model):
    __tablename__ = 'commands'
    id = db.Column(db.Integer, primary_key=True)
    system = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    endian = db.Column(db.String)
    parameters = db.relationship('CommandParameter', backref='command', cascade="all, delete-orphan")

class CommandParameter(db.Model):
    __tablename__ = 'command_parameters'
    id = db.Column(db.Integer, primary_key=True)
    command_id = db.Column(db.Integer, db.ForeignKey('commands.id'), nullable=False)
    name = db.Column(db.String, nullable=False)
    bit_length = db.Column(db.Integer)
    type = db.Column(db.String)
    min = db.Column(db.String)
    max = db.Column(db.String)
    default_value = db.Column(db.String)
    description = db.Column(db.String)
    is_array = db.Column(db.Boolean, default=False)
    array_length = db.Column(db.Integer, nullable=True)
    format_string = db.Column(db.String, nullable=True)
    endianness = db.Column(db.String, nullable=True)
    states = db.relationship('CommandParameterState', backref='parameter', cascade="all, delete-orphan")

class CommandParameterState(db.Model):
    __tablename__ = 'command_parameter_states'
    id = db.Column(db.Integer, primary_key=True)
    parameter_id = db.Column(db.Integer, db.ForeignKey('command_parameters.id'), nullable=False)
    state_name = db.Column(db.String)
    state_value = db.Column(db.String)

class TelemetryPacket(db.Model):
    __tablename__ = 'telemetry_packets'
    id = db.Column(db.Integer, primary_key=True)
    system = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)
    endian = db.Column(db.String)
    items = db.relationship('TelemetryItem', backref='packet', cascade="all, delete-orphan")

class TelemetryItem(db.Model):
    __tablename__ = 'telemetry_items'
    id = db.Column(db.Integer, primary_key=True)
    packet_id = db.Column(db.Integer, db.ForeignKey('telemetry_packets.id'), nullable=False)
    name = db.Column(db.String, nullable=False)
    bit_length = db.Column(db.Integer)
    type = db.Column(db.String)
    default_value = db.Column(db.String, nullable=True)
    description = db.Column(db.String, nullable=True)
    is_id_field = db.Column(db.Boolean, default=False)
    format_string = db.Column(db.String, nullable=True)
    units_name = db.Column(db.String, nullable=True)
    units_symbol = db.Column(db.String, nullable=True)
    endianness = db.Column(db.String, nullable=True)
    item_order = db.Column(db.Integer)
    states = db.relationship('TelemetryState', backref='item', cascade="all, delete-orphan")

class TelemetryState(db.Model):
    __tablename__ = 'telemetry_states'
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('telemetry_items.id'), nullable=False)
    state_name = db.Column(db.String, nullable=False)
    state_value = db.Column(db.String, nullable=False)

