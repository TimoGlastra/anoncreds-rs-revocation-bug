import {
	Schema,
	CredentialDefinition,
	RevocationRegistryDefinition,
	RevocationStatusList,
	CredentialOffer,
	CredentialRequest,
	LinkSecret,
	Credential,
	CredentialRevocationConfig,
	Presentation,
	CredentialRevocationState,
	anoncreds,
} from "@hyperledger/anoncreds-nodejs";
import assert from "node:assert";

const issuerId = "issuer:123";
const schemaId = `${issuerId}/schema`;
const credentialDefinitionId = `${issuerId}/definition`;
const revocationRegistryDefinitionId = `${issuerId}/revocation`;
const linkSecretId = "linkSecret";
const linkSecret = LinkSecret.create();

const schema = Schema.create({
	attributeNames: ["test"],
	issuerId,
	name: "test",
	version: "1.0",
});

const credentialDefinition = CredentialDefinition.create({
	issuerId,
	schema,
	schemaId,
	signatureType: "CL",
	tag: "tag",
	supportRevocation: true,
});

const revocationRegistryDefinition = RevocationRegistryDefinition.create({
	credentialDefinition: credentialDefinition.credentialDefinition,
	credentialDefinitionId,
	issuerId,
	maximumCredentialNumber: 100,
	revocationRegistryType: "CL_ACCUM",
	tag: "tag",
});

const statusList = RevocationStatusList.create({
	credentialDefinition: credentialDefinition.credentialDefinition,
	issuanceByDefault: true,
	issuerId,
	revocationRegistryDefinition:
		revocationRegistryDefinition.revocationRegistryDefinition,
	revocationRegistryDefinitionId,
	revocationRegistryDefinitionPrivate:
		revocationRegistryDefinition.revocationRegistryDefinitionPrivate,
	timestamp: 150,
});

function issueCredential(revocationIndex: number) {
	const offer = CredentialOffer.create({
		credentialDefinitionId,
		keyCorrectnessProof: credentialDefinition.keyCorrectnessProof,
		schemaId,
	});

	const request = CredentialRequest.create({
		credentialDefinition: credentialDefinition.credentialDefinition,
		credentialOffer: offer,
		linkSecret,
		linkSecretId,
		entropy: "885d238c-4846-4659-ad61-6546b5bf0fae",
	});

	const credential = Credential.create({
		attributeRawValues: {
			test: "hello",
		},
		credentialDefinition: credentialDefinition.credentialDefinition,
		credentialDefinitionPrivate:
			credentialDefinition.credentialDefinitionPrivate,
		credentialOffer: offer,
		credentialRequest: request.credentialRequest,
		revocationRegistryId: revocationRegistryDefinitionId,
		revocationStatusList: statusList,
		revocationConfiguration: new CredentialRevocationConfig({
			registryDefinition:
				revocationRegistryDefinition.revocationRegistryDefinition,
			registryDefinitionPrivate:
				revocationRegistryDefinition.revocationRegistryDefinitionPrivate,
			statusList: statusList,
			registryIndex: revocationIndex,
		}),
	});

	const processed = Credential.fromJson(credential.toJson()).process({
		credentialDefinition: credentialDefinition.credentialDefinition,
		linkSecret,
		credentialRequestMetadata: request.credentialRequestMetadata,
		revocationRegistryDefinition:
			revocationRegistryDefinition.revocationRegistryDefinition,
	});

	return processed;
}

function verifyCredential(credential: Credential) {
	const revocationState = CredentialRevocationState.create({
		revocationRegistryDefinition:
			revocationRegistryDefinition.revocationRegistryDefinition,
		revocationRegistryIndex: credential.revocationRegistryIndex as number,
		revocationStatusList: statusList,
		tailsPath:
			revocationRegistryDefinition.revocationRegistryDefinition.getTailsLocation(),
	});

	const presentationRequest = {
		name: "name",
		version: "1.0",
		nonce: anoncreds.generateNonce(),
		non_revoked: {
			from: 100,
			to: 200,
		},
		requested_attributes: {
			group: {
				names: ["test"],
				restrictions: [
					{
						cred_def_id: credentialDefinitionId,
					},
				],
			},
		},
		requested_predicates: {},
	};

	const presentation = Presentation.create({
		credentialDefinitions: {
			[credentialDefinitionId]:
				credentialDefinition.credentialDefinition.toJson(),
		},
		schemas: {
			[schemaId]: schema.toJson(),
		},
		linkSecret,
		credentials: [
			{
				credential: credential.toJson(),
				revocationState: revocationState.toJson(),
				timestamp: 150,
			},
		],
		credentialsProve: [
			{
				entryIndex: 0,
				reveal: true,
				isPredicate: false,
				referent: "group",
			},
		],
		presentationRequest,
		selfAttest: {},
	});

	return Presentation.fromJson(presentation.toJson()).verify({
		credentialDefinitions: {
			[credentialDefinitionId]: credentialDefinition.credentialDefinition,
		},
		schemas: {
			[schemaId]: schema,
		},
		presentationRequest,
		revocationRegistryDefinitions: {
			[revocationRegistryDefinitionId]:
				revocationRegistryDefinition.revocationRegistryDefinition,
		},
		nonRevokedIntervalOverrides: [
			{
				requestedFromTimestamp: 100,
				overrideRevocationStatusListTimestamp: 150,
				revocationRegistryDefinitionId,
			},
		],
		revocationStatusLists: [statusList],
	});
}

function revokeCredential(revocationIndex: number) {
	statusList.update({
		credentialDefinition: credentialDefinition.credentialDefinition,
		revocationRegistryDefinition:
			revocationRegistryDefinition.revocationRegistryDefinition,
		revocationRegistryDefinitionPrivate:
			revocationRegistryDefinition.revocationRegistryDefinitionPrivate,
		// We use the same timestamp, as that's not what we're testing here
		timestamp: 150,
		revoked: [revocationIndex],
	});
	console.log(statusList.toJson());
}

const credential1 = issueCredential(1);
const credential2 = issueCredential(2);

// Both should succeed
assert.equal(verifyCredential(credential1), true);
assert.equal(verifyCredential(credential2), true);

// Revoke a credential
revokeCredential(1);

// This one should fail now, as it's revoked
assert.equal(verifyCredential(credential1), false);

// This one should still succeed
assert.equal(verifyCredential(credential2), true);
