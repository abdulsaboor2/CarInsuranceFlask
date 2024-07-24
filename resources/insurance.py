from flask import request
from flask_restful import Resource
from models import db, Insurance

class InsuranceResource(Resource):
    def get(self, insurance_id=None):
        if insurance_id:
            insurance = Insurance.query.get_or_404(insurance_id)
            return {"id": insurance.id, "name": insurance.name, "car_make": insurance.car_make, "car_model": insurance.car_model, "car_year": insurance.car_year, "policy_number": insurance.policy_number}
        else:
            insurances = Insurance.query.all()
            return [{"id": insur.id, "name": insur.name, "car_make": insur.car_make, "car_model": insur.car_model, "car_year": insur.car_year, "policy_number": insur.policy_number} for insur in insurances]

    def post(self):
        data = request.get_json()
        new_insurance = Insurance(name=data['name'], car_make=data['car_make'], car_model=data['car_model'], car_year=data['car_year'], policy_number=data['policy_number'])
        db.session.add(new_insurance)
        db.session.commit()
        return {"message": "Insurance added", "insurance": {"id": new_insurance.id, "name": new_insurance.name, "car_make": new_insurance.car_make, "car_model": new_insurance.car_model, "car_year": new_insurance.car_year, "policy_number": new_insurance.policy_number}}, 201

    def put(self, insurance_id):
        data = request.get_json()
        insurance = Insurance.query.get_or_404(insurance_id)
        insurance.name = data['name']
        insurance.car_make = data['car_make']
        insurance.car_model = data['car_model']
        insurance.car_year = data['car_year']
        insurance.policy_number = data['policy_number']
        db.session.commit()
        return {"message": "Insurance updated", "insurance": {"id": insurance.id, "name": insurance.name, "car_make": insurance.car_make, "car_model": insurance.car_model, "car_year": insurance.car_year, "policy_number": insurance.policy_number}}

    def delete(self, insurance_id):
        insurance = Insurance.query.get_or_404(insurance_id)
        db.session.delete(insurance)
        db.session.commit()
        return {"message": "Insurance deleted"}
