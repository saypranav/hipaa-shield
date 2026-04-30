import json, requests, glob, itertools

BASE = "http://localhost:9901/openmrs/ws/rest/v1"
AUTH = ("admin", "Admin123")

IDENTIFIER_TYPE_UUID = "8d79403a-c2cc-11de-8d13-0010c6dffd0f"
LOCATION_UUID = "aff27d58-a15c-49a6-9beb-d30dcfc0c66e"

counter = itertools.count(1000)

def import_patient(fhir_patient, identifier):
    name = fhir_patient.get("name", [{}])[0]
    gender = fhir_patient.get("gender", "unknown")
    gender_map = {"male": "M", "female": "F", "other": "O", "unknown": "U"}

    payload = {
        "person": {
            "names": [{
                "givenName": name.get("given", ["Unknown"])[0],
                "familyName": name.get("family", "Unknown")
            }],
            "gender": gender_map.get(gender, "U"),
            "birthdate": fhir_patient.get("birthDate", "1900-01-01"),
            "addresses": [{
                "address1": fhir_patient.get("address", [{}])[0].get("line", [""])[0],
                "cityVillage": fhir_patient.get("address", [{}])[0].get("city", ""),
                "stateProvince": fhir_patient.get("address", [{}])[0].get("state", ""),
                "country": fhir_patient.get("address", [{}])[0].get("country", "")
            }]
        },
        "identifiers": [{
            "identifier": str(identifier),
            "identifierType": IDENTIFIER_TYPE_UUID,
            "location": LOCATION_UUID,
            "preferred": True
        }]
    }

    # DEBUG — print exact payload before sending
    print(f"  SENDING: {json.dumps(payload['identifiers'])}")

    r = requests.post(f"{BASE}/patient", json=payload, auth=AUTH)
    return r.status_code, r.json()

success, fail = 0, 0

for bundle_file in glob.glob("synthea/output/fhir/*.json"):
    with open(bundle_file) as f:
        bundle = json.load(f)
    for entry in bundle.get("entry", []):
        resource = entry.get("resource", {})
        if resource.get("resourceType") == "Patient":
            identifier = next(counter)
            status, response = import_patient(resource, identifier)
            if status == 201:
                success += 1
                print(f"  OK  → {response.get('display')}")
            else:
                fail += 1
                print(f"  FAIL [{status}] → {response['error']['globalErrors']}")

print(f"\nDone: {success} imported, {fail} failed")