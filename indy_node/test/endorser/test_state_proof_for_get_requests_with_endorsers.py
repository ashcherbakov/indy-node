import json

from indy.ledger import build_get_revoc_reg_def_request, build_nym_request, build_attrib_request

from indy_node.server.request_handlers.domain_req_handlers.revoc_reg_def_handler import RevocRegDefHandler
from indy_node.test.anon_creds.helper import get_revoc_reg_def_id, create_revoc_reg, get_cred_def_id

from common.serializers.serialization import domain_state_serializer
from indy_node.test.api.helper import sdk_build_schema_request
from indy_node.test.endorser.helper import sdk_submit_and_check_by_endorser
from indy_node.test.helper import createHalfKeyIdentifierAndAbbrevVerkey
from plenum.common.constants import TARGET_NYM, TXN_TYPE, RAW, DATA, \
    ROLE, VERKEY, TXN_TIME, NAME, VERSION, CURRENT_PROTOCOL_VERSION
from plenum.common.types import f

from indy_node.test.state_proof.helper import check_valid_proof, \
    sdk_submit_operation_and_get_result
from indy_common.constants import GET_ATTR, GET_NYM, GET_SCHEMA, \
    CLAIM_DEF, REVOCATION, GET_CLAIM_DEF, CLAIM_DEF_SIGNATURE_TYPE, CLAIM_DEF_SCHEMA_REF, CLAIM_DEF_FROM, \
    SCHEMA_ATTR_NAMES, CLAIM_DEF_TAG, ISSUANCE_BY_DEFAULT
from indy_common.serialization import attrib_raw_data_serializer

# Fixtures, do not remove
from plenum.common.util import randomString
from plenum.test.helper import sdk_get_and_check_replies, sdk_sign_and_submit_req, sdk_gen_request

from indy_node.test.anon_creds.conftest import send_revoc_reg_entry, send_revoc_reg_def, send_claim_def, claim_def
from indy_node.test.schema.test_send_get_schema import send_schema_req, send_schema_seq_no
from indy_node.test.state_proof.conftest import nodeSetWithOneNodeResponding


def test_state_proof_returned_for_get_attr(looper,
                                           nodeSet,
                                           sdk_pool_handle,
                                           sdk_wallet_client,
                                           sdk_wallet_new_client,
                                           sdk_wallet_endorser):
    """
    Tests that state proof is returned in the reply for GET_ATTR transactions.
    Use different submitter and reader!
    """
    # Add Attrib
    raw = json.dumps({'answer': 42})
    req_json = looper.loop.run_until_complete(
        build_attrib_request(sdk_wallet_new_client[1], sdk_wallet_new_client[1], None, raw, None))
    sdk_submit_and_check_by_endorser(looper, sdk_pool_handle,
                                     sdk_wallet_author=sdk_wallet_new_client, sdk_wallet_endorser=sdk_wallet_endorser,
                                     request_json=req_json)

    # Get Attrib
    get_attr_operation = {
        TARGET_NYM: sdk_wallet_new_client[1],
        TXN_TYPE: GET_ATTR,
        RAW: 'answer'
    }

    result = sdk_submit_operation_and_get_result(looper, sdk_pool_handle,
                                                 sdk_wallet_client,
                                                 get_attr_operation)

    # Check
    assert DATA in result
    data = attrib_raw_data_serializer.deserialize(result[DATA])
    assert data['answer'] == 42
    assert result.get(f.ENDORSER.nm) == sdk_wallet_endorser[1]
    assert result[TXN_TIME]
    check_valid_proof(result)


def test_state_proof_returned_for_get_nym(looper,
                                          nodeSet,
                                          sdk_pool_handle,
                                          sdk_wallet_client,
                                          sdk_wallet_endorser,
                                          sdk_wallet_new_client):
    """
    Tests that state proof is returned in the reply for GET_NYM transactions.
    Use different submitter and reader!
    """
    # add NYM
    idr, verkey = createHalfKeyIdentifierAndAbbrevVerkey()
    req_json = looper.loop.run_until_complete(build_nym_request(sdk_wallet_new_client[1], idr, verkey, None, None))
    sdk_submit_and_check_by_endorser(looper, sdk_pool_handle,
                                     sdk_wallet_author=sdk_wallet_new_client, sdk_wallet_endorser=sdk_wallet_endorser,
                                     request_json=req_json)

    # Get NYM
    get_nym_operation = {
        TARGET_NYM: idr,
        TXN_TYPE: GET_NYM
    }

    result = sdk_submit_operation_and_get_result(looper, sdk_pool_handle,
                                                 sdk_wallet_client,
                                                 get_nym_operation)

    # Check
    assert DATA in result
    assert result[DATA]
    data = domain_state_serializer.deserialize(result[DATA])
    assert ROLE in data
    assert VERKEY in data
    assert f.IDENTIFIER.nm in data
    assert result[TXN_TIME]
    check_valid_proof(result)
    assert result.get(f.ENDORSER.nm) == sdk_wallet_endorser[1]


def test_state_proof_returned_for_get_schema(looper,
                                             nodeSet,
                                             sdk_wallet_endorser,
                                             sdk_pool_handle,
                                             sdk_wallet_client,
                                             sdk_wallet_new_client):
    """
    Tests that state proof is returned in the reply for GET_SCHEMA transactions.
    Use different submitter and reader!
    """
    # add Schema
    req_json, _ = sdk_build_schema_request(looper, sdk_wallet_new_client,
                                           ["attr1"], "name1", "1.0")
    sdk_submit_and_check_by_endorser(looper, sdk_pool_handle,
                                     sdk_wallet_author=sdk_wallet_new_client, sdk_wallet_endorser=sdk_wallet_endorser,
                                     request_json=req_json)

    # get Schema
    get_schema_operation = {
        TARGET_NYM: sdk_wallet_new_client[1],
        TXN_TYPE: GET_SCHEMA,
        DATA: {
            NAME: "name1",
            VERSION: "1.0",
        }
    }
    result = sdk_submit_operation_and_get_result(looper, sdk_pool_handle,
                                                 sdk_wallet_client,
                                                 get_schema_operation)
    # Check
    assert DATA in result
    data = result.get(DATA)
    assert data
    assert data[SCHEMA_ATTR_NAMES] == ["attr1"]
    assert data[NAME] == "name1"
    assert data[VERSION] == "1.0"
    assert result.get(f.ENDORSER.nm) == sdk_wallet_endorser[1]
    assert result[TXN_TIME]
    check_valid_proof(result)


def test_state_proof_returned_for_get_claim_def(looper,
                                                nodeSet,
                                                sdk_wallet_endorser,
                                                sdk_pool_handle,
                                                sdk_wallet_client,
                                                send_schema_seq_no,
                                                sdk_wallet_new_client):
    """
    Tests that state proof is returned in the reply for GET_CLAIM_DEF
    transactions.
    Use different submitter and reader!
    """
    # add Claim Def
    _, dest = sdk_wallet_endorser
    data = {"primary": {'N': '123'}, REVOCATION: {'h0': '456'}}
    claim_def_operation = {
        TXN_TYPE: CLAIM_DEF,
        CLAIM_DEF_SCHEMA_REF: send_schema_seq_no,
        DATA: data,
        CLAIM_DEF_SIGNATURE_TYPE: 'CL',
        CLAIM_DEF_TAG: "tag1"
    }
    req_obj = sdk_gen_request(claim_def_operation, protocol_version=CURRENT_PROTOCOL_VERSION,
                              identifier=sdk_wallet_new_client[1])
    req_json = json.dumps(req_obj.as_dict)
    sdk_submit_and_check_by_endorser(looper, sdk_pool_handle,
                                     sdk_wallet_author=sdk_wallet_new_client, sdk_wallet_endorser=sdk_wallet_endorser,
                                     request_json=req_json)

    # get claim def
    get_claim_def_operation = {
        CLAIM_DEF_FROM: sdk_wallet_new_client[1],
        TXN_TYPE: GET_CLAIM_DEF,
        CLAIM_DEF_SCHEMA_REF: send_schema_seq_no,
        CLAIM_DEF_SIGNATURE_TYPE: 'CL',
        CLAIM_DEF_TAG: "tag1"
    }
    result = sdk_submit_operation_and_get_result(looper,
                                                 sdk_pool_handle,
                                                 sdk_wallet_client,
                                                 get_claim_def_operation)
    # check
    expected_data = data
    assert DATA in result
    data = result.get(DATA)
    assert data
    assert expected_data.items() <= data.items()
    assert result.get(f.ENDORSER.nm) == sdk_wallet_endorser[1]
    assert result[TXN_TIME]
    check_valid_proof(result)


def test_state_proof_returned_for_get_revoc_reg_def(looper,
                                                    nodeSet,
                                                    sdk_wallet_endorser,
                                                    sdk_pool_handle,
                                                    sdk_wallet_client,
                                                    sdk_wallet_new_client,
                                                    send_claim_def):
    # Add RevocRegDef
    cred_def_id = get_cred_def_id(send_claim_def[0][f.IDENTIFIER.nm],
                                  send_claim_def[0]['operation']['ref'],
                                  send_claim_def[0]['operation']['tag'])
    tag = randomString(5)
    req_json = create_revoc_reg(looper, sdk_wallet_new_client[0], sdk_wallet_new_client[1], tag,
                                cred_def_id,
                                ISSUANCE_BY_DEFAULT)
    sdk_submit_and_check_by_endorser(looper, sdk_pool_handle,
                                     sdk_wallet_author=sdk_wallet_new_client, sdk_wallet_endorser=sdk_wallet_endorser,
                                     request_json=req_json)

    req = looper.loop.run_until_complete(
        build_get_revoc_reg_def_request(sdk_wallet_client[1],
                                        RevocRegDefHandler.make_state_path_for_revoc_def(sdk_wallet_new_client[1],
                                                                                         cred_def_id,
                                                                                         ISSUANCE_BY_DEFAULT,
                                                                                         tag).decode()
                                        )
    )
    rep = sdk_get_and_check_replies(looper, [sdk_sign_and_submit_req(sdk_pool_handle, sdk_wallet_client, req)])
    result = rep[0][1]['result']

    assert DATA in result
    assert result[TXN_TIME]
    check_valid_proof(result)
    assert result[DATA].get(f.ENDORSER.nm) == sdk_wallet_endorser[1]
#
#
# def test_state_proof_returned_for_get_revoc_reg_entry(looper,
#                                                       nodeSetWithOneNodeResponding,
#                                                       sdk_wallet_endorser,
#                                                       sdk_pool_handle,
#                                                       sdk_wallet_client,
#                                                       send_revoc_reg_entry):
#     revoc_reg_def = send_revoc_reg_entry[0]
#     revoc_reg_entry_data = send_revoc_reg_entry[1][0]['operation']
#
#     timestamp = int(time.time())
#     req = looper.loop.run_until_complete(build_get_revoc_reg_request(
#         sdk_wallet_client[1], get_revoc_reg_def_id(sdk_wallet_steward[1], revoc_reg_def[0]), timestamp))
#     rep = sdk_get_and_check_replies(looper, [sdk_sign_and_submit_req(sdk_pool_handle, sdk_wallet_client, req)])
#     result = rep[0][1]['result']
#
#     expected_data = revoc_reg_entry_data
#     data = result.get(DATA)
#
#     del expected_data['type']
#     del data['seqNo']
#     del data['txnTime']
#     assert DATA in result
#     assert data
#     assert data == expected_data
#     assert result[TXN_TIME]
#     check_valid_proof(result)
#     if endorser:
#         assert result.get(f.ENDORSER.nm) == sdk_wallet_endorser[1]
#
#
# def check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, timestamp_fr, timestamp_to,
#                     sdk_pool_handle, revoc_reg_entry_data, check_data=True):
#     req = looper.loop.run_until_complete(build_get_revoc_reg_delta_request(
#         sdk_wallet_client[1], get_revoc_reg_def_id(sdk_wallet_steward[1], revoc_reg_def[0]), timestamp_fr,
#         timestamp_to))
#     rep = sdk_get_and_check_replies(looper, [sdk_sign_and_submit_req(sdk_pool_handle, sdk_wallet_client, req)])
#
#     if check_data:
#         result = rep[0][1]['result']
#         expected_data = revoc_reg_entry_data
#         data = result.get(DATA)['value']['accum_to']
#
#         del data['seqNo']
#         del data['txnTime']
#         if 'type' in expected_data:
#             del expected_data['type']
#         assert DATA in result
#         assert data
#         assert data == expected_data
#         assert result[TXN_TIME]
#         check_valid_proof(result)
#
#
# def test_state_proof_returned_for_get_revoc_reg_delta(looper,
#                                                       nodeSetWithOneNodeResponding,
#                                                       sdk_wallet_steward,
#                                                       sdk_pool_handle,
#                                                       sdk_wallet_client,
#                                                       send_revoc_reg_entry):
#     revoc_reg_def = send_revoc_reg_entry[0]
#     revoc_reg_entry_data = send_revoc_reg_entry[1][0]['operation']
#     timestamp = send_revoc_reg_entry[1][1]['result']['txnMetadata']['txnTime']
#
#     check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, None, timestamp + 1,
#                     sdk_pool_handle, revoc_reg_entry_data)
#
#     check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, None, timestamp - 1,
#                     sdk_pool_handle, revoc_reg_entry_data, False)
#
#     # TODO: INDY-2115
#     # check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, timestamp - 2, timestamp - 1,
#     #                 sdk_pool_handle, revoc_reg_entry_data, False)
#
#     # check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, timestamp - 1, timestamp + 1,
#     #                 sdk_pool_handle, revoc_reg_entry_data)
#
#     check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, timestamp + 1, timestamp + 2,
#                     sdk_pool_handle, revoc_reg_entry_data)
#
#     # TODO: INDY-2115
#     # check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, None, timestamp - 999,
#     #                 sdk_pool_handle, revoc_reg_entry_data)
#     #
#     # check_get_delta(looper, sdk_wallet_client, sdk_wallet_steward, revoc_reg_def, timestamp - 1000, timestamp - 999,
#     #                 sdk_pool_handle, revoc_reg_entry_data)
