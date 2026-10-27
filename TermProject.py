"""
Cyber Incident Tracker
A command-line application for recording, reviewing, and reporting cybersecurity incidents.

Author: Student Name
Course: IT 215
Python version: 3.9+
Uses Python standard-library modules only.
"""

import csv
import json
from datetime import datetime
from pathlib import Path

DATA_FILE = Path("incidents.json")
EXPORT_FILE = Path("incident_report.csv")

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")
VALID_STATUSES = ("Open", "Investigating", "Contained", "Resolved")


class SecurityIncident:
    """Represent one cybersecurity incident."""

    def __init__(self, incident_id, title, category, severity, description,
                 reported_by, date_reported=None, status="Open"):
        self.incident_id = incident_id
        self.title = title
        self.category = category
        self.severity = severity
        self.description = description
        self.reported_by = reported_by
        self.date_reported = date_reported or datetime.now().strftime("%Y-%m-%d %H:%M")
        self.status = status

    def to_dict(self):
        """Convert an incident object into a dictionary for JSON storage."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "reported_by": self.reported_by,
            "date_reported": self.date_reported,
            "status": self.status,
        }

    @classmethod
    def from_dict(cls, data):
        """Create an incident object from a saved dictionary."""
        return cls(
            incident_id=data["incident_id"],
            title=data["title"],
            category=data["category"],
            severity=data["severity"],
            description=data["description"],
            reported_by=data["reported_by"],
            date_reported=data.get("date_reported"),
            status=data.get("status", "Open"),
        )

    def risk_score(self):
        """Return a simple severity score for prioritization, not a formal risk rating."""
        scores = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return scores.get(self.severity, 0)


def load_incidents():
    """Read incident records from JSON and recover gracefully from file errors."""
    if not DATA_FILE.exists():
        return []

    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            raw_records = json.load(file)
        if not isinstance(raw_records, list):
            raise ValueError("The data file must contain a list of incidents.")
        incidents = []
        for record in raw_records:
            try:
                incidents.append(SecurityIncident.from_dict(record))
            except (KeyError, TypeError) as error:
                print(f"Warning: skipped an invalid incident record ({error}).")
        return incidents
    except (json.JSONDecodeError, OSError, ValueError) as error:
        print(f"Could not read saved incidents: {error}")
        print("The program will continue with an empty in-memory list.")
        return []


def save_incidents(incidents):
    """Save incident records to a temporary file before replacing the main file."""
    temporary_file = DATA_FILE.with_suffix(".tmp")
    try:
        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump([incident.to_dict() for incident in incidents], file, indent=4)
        temporary_file.replace(DATA_FILE)
        return True
    except OSError as error:
        print(f"Error saving incidents: {error}")
        try:
            if temporary_file.exists():
                temporary_file.unlink()
        except OSError:
            pass
        return False


def get_nonempty_input(prompt):
    """Keep asking until the user enters nonblank text."""
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("This field cannot be blank. Please try again.")


def choose_from_list(prompt, options):
    """Ask the user to choose one item from a list of allowed options."""
    while True:
        print(prompt)
        for number, option in enumerate(options, start=1):
            print(f"  {number}. {option}")
        choice = input("Enter a number: ").strip()
        try:
            index = int(choice) - 1
            if 0 <= index < len(options):
                return options[index]
            print(f"Choose a number from 1 to {len(options)}.")
        except ValueError:
            print("Please enter a whole number.")


def next_incident_id(incidents):
    """Generate the next numeric incident ID."""
    existing_ids = []
    for incident in incidents:
        try:
            existing_ids.append(int(incident.incident_id))
        except (ValueError, TypeError):
            continue
    return str(max(existing_ids, default=1000) + 1)


def add_incident(incidents):
    """Collect details, create an object, and save a new incident."""
    print("\n--- Record a Cybersecurity Incident ---")
    incident = SecurityIncident(
        incident_id=next_incident_id(incidents),
        title=get_nonempty_input("Incident title: "),
        category=choose_from_list(
            "Choose a category:",
            ["Phishing", "Malware", "Unauthorized Access", "Lost Device",
             "Data Exposure", "Suspicious Activity", "Other"],
        ),
        severity=choose_from_list("Choose severity:", SEVERITY_LEVELS),
        description=get_nonempty_input("Describe what happened: "),
        reported_by=get_nonempty_input("Reported by (name or team): "),
    )
    incidents.append(incident)
    if save_incidents(incidents):
        print(f"Incident #{incident.incident_id} saved successfully.")
    else:
        incidents.pop()
        print("The incident was not added because it could not be saved.")


def display_incident(incident):
    """Print one incident in a readable format."""
    print("-" * 56)
    print(f"ID: {incident.incident_id} | Title: {incident.title}")
    print(f"Category: {incident.category} | Severity: {incident.severity}")
    print(f"Status: {incident.status} | Risk priority score: {incident.risk_score()}/4")
    print(f"Reported by: {incident.reported_by} | Date: {incident.date_reported}")
    print(f"Description: {incident.description}")


def list_incidents(incidents):
    """Display all incident records, ordered by severity and then date."""
    print("\n--- Incident Register ---")
    if not incidents:
        print("No incidents have been recorded yet.")
        return
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    for incident in sorted(
        incidents, key=lambda item: (severity_order.get(item.severity, 4), item.date_reported)
    ):
        display_incident(incident)
    print("-" * 56)


def search_incidents(incidents):
    """Search incident titles, descriptions, categories, and statuses."""
    term = get_nonempty_input("Enter a keyword, category, or status: ").casefold()
    matches = [
        incident for incident in incidents
        if term in incident.title.casefold()
        or term in incident.description.casefold()
        or term in incident.category.casefold()
        or term in incident.status.casefold()
        or term in incident.severity.casefold()
    ]
    if not matches:
        print("No matching incidents were found.")
        return
    print(f"\nFound {len(matches)} matching incident(s):")
    for incident in matches:
        display_incident(incident)


def update_incident_status(incidents):
    """Change the status of an existing incident."""
    if not incidents:
        print("There are no incidents to update.")
        return
    incident_id = get_nonempty_input("Enter the incident ID to update: ")
    incident = next((item for item in incidents if item.incident_id == incident_id), None)
    if incident is None:
        print("No incident was found with that ID.")
        return

    new_status = choose_from_list("Choose the new status:", VALID_STATUSES)
    old_status = incident.status
    incident.status = new_status
    if save_incidents(incidents):
        print(f"Incident #{incident_id} status changed from {old_status} to {new_status}.")
    else:
        incident.status = old_status
        print("The status change was canceled because saving failed.")


def show_summary(incidents):
    """Display totals by severity and status."""
    print("\n--- Incident Summary ---")
    print(f"Total incidents: {len(incidents)}")
    if not incidents:
        print("Add an incident to start building a summary.")
        return
    for severity in SEVERITY_LEVELS:
        count = sum(1 for incident in incidents if incident.severity == severity)
        print(f"{severity}: {count}")
    print("\nStatus totals:")
    for status in VALID_STATUSES:
        count = sum(1 for incident in incidents if incident.status == status)
        print(f"{status}: {count}")
    open_critical = sum(
        1 for incident in incidents
        if incident.severity == "Critical" and incident.status != "Resolved"
    )
    print(f"\nUnresolved critical incidents: {open_critical}")


def export_csv(incidents):
    """Export incident records to a CSV report that can be opened in a spreadsheet."""
    fieldnames = [
        "incident_id", "title", "category", "severity", "description",
        "reported_by", "date_reported", "status",
    ]
    try:
        with EXPORT_FILE.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            for incident in incidents:
                writer.writerow(incident.to_dict())
        print(f"Export complete: {EXPORT_FILE.resolve()}")
    except OSError as error:
        print(f"Could not export the report: {error}")


def show_menu():
    """Display the main menu and return the user's selection."""
    print("\n" + "=" * 42)
    print("       CYBER INCIDENT TRACKER")
    print("=" * 42)
    print("1. Record a new incident")
    print("2. View all incidents")
    print("3. Search incidents")
    print("4. Update incident status")
    print("5. View summary report")
    print("6. Export report to CSV")
    print("7. Save and exit")
    return input("Choose an option (1-7): ").strip()


def main():
    """Run the application's menu loop."""
    incidents = load_incidents()
    print("Welcome to Cyber Incident Tracker.")
    print(f"Loaded {len(incidents)} saved incident(s).")

    while True:
        choice = show_menu()
        if choice == "1":
            add_incident(incidents)
        elif choice == "2":
            list_incidents(incidents)
        elif choice == "3":
            search_incidents(incidents)
        elif choice == "4":
            update_incident_status(incidents)
        elif choice == "5":
            show_summary(incidents)
        elif choice == "6":
            export_csv(incidents)
        elif choice == "7":
            save_incidents(incidents)
            print("Your incident data has been saved. Goodbye.")
            break
        else:
            print("Invalid selection. Enter a number from 1 through 7.")


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print("\nProgram stopped by user. Any previously saved data remains available.")
