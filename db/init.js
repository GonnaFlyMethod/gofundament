db.createCollection('accounts', {
	validator: {
		$jsonSchema: {
			bsonType: 'object',
			title: 'accounts',
			required: ['nickname', 'email', 'birth_date', 'current_country', 'created_at', 'updated_at', 'encrypted_password'],
			properties: {
				first_name: {
					bsonType: 'string'
				},
				last_name: {
					bsonType: 'string'
				},
				nickname: {
					bsonType: 'string'
				},
				email: {
					bsonType: 'string'
				},
				birth_date: {
					bsonType: 'date'
				},
				current_country: {
					bsonType: 'string'
				},
				created_at: {
					bsonType: 'timestamp'
				},
				updated_at: {
					bsonType: 'timestamp'
				},
				encrypted_password: {
					bsonType: 'binData'
				},
			}
		}
	}
});

db.accounts.createIndex( { "nickname": 1 }, { unique: true } )
db.accounts.createIndex( { "email": 1 }, { unique: true } )

db.createCollection('sessions', {
	validator: {
		$jsonSchema: {
			bsonType: 'object',
			title: 'sessions',
			required: ['account_id'],
			properties: {
				account_id: {
					bsonType: 'binData'
				},
			}
		}
	}
});
