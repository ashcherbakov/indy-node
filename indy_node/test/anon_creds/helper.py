import json

from indy import blob_storage
from indy.anoncreds import issuer_create_and_store_revoc_reg
from indy.ledger import build_revoc_reg_def_request, build_revoc_reg_entry_request

from indy_common.state.state_constants import MARKER_CLAIM_DEF, MARKER_REVOC_DEF, MARKER_REVOC_REG_ENTRY
from indy_node.server.request_handlers.domain_req_handlers.revoc_reg_def_handler import RevocRegDefHandler
from indy_node.server.request_handlers.domain_req_handlers.revoc_reg_entry_handler import RevocRegEntryHandler
from plenum.common.types import f

from plenum.common.constants import STATE_PROOF, ROOT_HASH, MULTI_SIGNATURE, PROOF_NODES, MULTI_SIGNATURE_SIGNATURE, \
    MULTI_SIGNATURE_PARTICIPANTS, MULTI_SIGNATURE_VALUE, MULTI_SIGNATURE_VALUE_LEDGER_ID, \
    MULTI_SIGNATURE_VALUE_STATE_ROOT, MULTI_SIGNATURE_VALUE_TXN_ROOT, MULTI_SIGNATURE_VALUE_POOL_STATE_ROOT, \
    MULTI_SIGNATURE_VALUE_TIMESTAMP, TYPE, DATA, TXN_TIME, TXN_PAYLOAD, TXN_PAYLOAD_METADATA, TXN_PAYLOAD_METADATA_FROM, \
    TXN_PAYLOAD_DATA, TXN_METADATA, TXN_METADATA_SEQ_NO, TXN_METADATA_TIME
from indy_common.constants import VALUE, GET_REVOC_REG_DEF, GET_REVOC_REG, GET_REVOC_REG_DELTA, \
    ACCUM_TO, ISSUED, STATE_PROOF_FROM, ACCUM_FROM, CRED_DEF_ID, REVOC_TYPE, TAG, REVOC_REG_DEF_ID
from common.serializers.serialization import state_roots_serializer, proof_nodes_serializer
from plenum.server.request_handlers.utils import encode_state_value
from state.pruning_state import PruningState


def get_cred_def_id(submitter_did, schema_id, tag):
    cred_def_marker = MARKER_CLAIM_DEF
    signature_type = 'CL'
    cred_def_id = ':'.join([submitter_did, cred_def_marker, signature_type, str(schema_id), tag])
    return cred_def_id


def get_revoc_reg_def_id(author_did, revoc_req):
    return ":".join([author_did,
                     MARKER_REVOC_DEF,
                     revoc_req['operation'][CRED_DEF_ID],
                     revoc_req['operation'][REVOC_TYPE],
                     revoc_req['operation'][TAG]])


def get_revoc_reg_entry_id(submitter_did, def_revoc_id):
    entry_revoc_id = ':'.join([submitter_did, MARKER_REVOC_REG_ENTRY, def_revoc_id])
    return entry_revoc_id


def create_revoc_reg(looper, wallet_handle, submitter_did, tag, cred_def_id,
                     issuance):
    tails_writer_config = json.dumps({'base_dir': 'tails', 'uri_pattern': ''})
    tails_writer = looper.loop.run_until_complete(blob_storage.open_writer(
        'default', tails_writer_config))
    _, revoc_reg_def_json, revoc_reg_entry_json = \
        looper.loop.run_until_complete(issuer_create_and_store_revoc_reg(
            wallet_handle, submitter_did, "CL_ACCUM", tag, cred_def_id,
            json.dumps({"max_cred_num": 5, "issuance_type": issuance}),
            tails_writer))
    return looper.loop.run_until_complete(
        build_revoc_reg_def_request(submitter_did, revoc_reg_def_json))


def create_revoc_reg_entry(looper, wallet_handle, submitter_did, tag, cred_def_id,
                           issuance):
    tails_writer_config = json.dumps({'base_dir': 'tails', 'uri_pattern': ''})
    tails_writer = looper.loop.run_until_complete(blob_storage.open_writer(
        'default', tails_writer_config))
    revoc_reg_def_id, revoc_reg_def_json, revoc_reg_entry_json = \
        looper.loop.run_until_complete(issuer_create_and_store_revoc_reg(
            wallet_handle, submitter_did, "CL_ACCUM", tag, cred_def_id,
            json.dumps({"max_cred_num": 5, "issuance_type": issuance}),
            tails_writer))
    revoc_reg_def = looper.loop.run_until_complete(
        build_revoc_reg_def_request(submitter_did, revoc_reg_def_json))
    entry_revoc_request = looper.loop.run_until_complete(
        build_revoc_reg_entry_request(
            submitter_did, revoc_reg_def_id, "CL_ACCUM", revoc_reg_entry_json))

    return revoc_reg_def, entry_revoc_request


def prepare_for_state(result):
    request_type = result[TYPE]
    if request_type == GET_REVOC_REG_DEF:
        return prepare_get_revoc_def_for_state(result)
    if request_type == GET_REVOC_REG:
        return prepare_get_revoc_reg_entry_accum_for_state(result)
    if request_type == GET_REVOC_REG_DELTA:
        if ISSUED in result[DATA][VALUE]:
            return prepare_get_revoc_reg_entry_for_state(result)
        else:
            return prepare_get_revoc_reg_entry_accum_for_state(result)
    raise ValueError("Cannot make state key for "
                     "request of type {}"
                     .format(request_type))

def prepare_get_revoc_def_for_state(reply):
    author_did = reply.get(f.IDENTIFIER.nm)
    cred_def_id = reply.get(DATA).get(CRED_DEF_ID)
    revoc_def_type = reply.get(DATA).get(REVOC_TYPE)
    revoc_def_tag = reply.get(DATA).get(TAG)
    endorser = reply.get(f.ENDORSER.nm)
    assert author_did
    assert cred_def_id
    assert revoc_def_type
    assert revoc_def_tag
    path = RevocRegDefHandler.make_state_path_for_revoc_def(author_did,
                                         cred_def_id,
                                         revoc_def_type,
                                         revoc_def_tag)
    seq_no = reply[f.SEQ_NO.nm]
    txn_time = reply[TXN_TIME]
    assert seq_no
    assert txn_time
    value_bytes = encode_state_value(reply[DATA], seq_no, txn_time, endorser)
    return path, value_bytes


def prepare_get_revoc_reg_entry_for_state(reply):
    revoc_reg_def_id = reply.get(DATA).get(REVOC_REG_DEF_ID)
    assert revoc_reg_def_id
    path = RevocRegEntryHandler.make_state_path_for_revoc_reg_entry(revoc_reg_def_id=revoc_reg_def_id)

    seq_no = reply[f.SEQ_NO.nm]
    txn_time = reply[TXN_TIME]
    endorser = reply.get(f.ENDORSER.nm)
    assert seq_no
    assert txn_time
    value_bytes = encode_state_value(reply[DATA], seq_no, txn_time, endorser)
    return path, value_bytes


def prepare_get_revoc_reg_entry_accum_for_state(reply):
    revoc_reg_def_id = reply.get(DATA).get(REVOC_REG_DEF_ID)
    seq_no = reply[f.SEQ_NO.nm]
    txn_time = reply[TXN_TIME]
    endorser = reply.get(f.ENDORSER.nm)
    assert revoc_reg_def_id
    assert seq_no
    assert txn_time
    path = RevocRegEntryHandler.make_state_path_for_revoc_reg_entry_accum(revoc_reg_def_id=revoc_reg_def_id)

    value_bytes = encode_state_value(reply[DATA], seq_no, txn_time, endorser)
    return path, value_bytes

def validate_proof(result):
    """
    Validates state proof
    """
    state_root_hash = result[STATE_PROOF]['root_hash']
    state_root_hash = state_roots_serializer.deserialize(state_root_hash)
    proof_nodes = result[STATE_PROOF]['proof_nodes']
    if isinstance(proof_nodes, str):
        proof_nodes = proof_nodes.encode()
    proof_nodes = proof_nodes_serializer.deserialize(proof_nodes)
    key, value = prepare_for_state(result)
    valid = PruningState.verify_state_proof(state_root_hash,
                                            key,
                                            value,
                                            proof_nodes,
                                            serialized=True)
    return valid


def check_valid_proof(reply):
    result = reply['result']
    assert STATE_PROOF in result

    state_proof = result[STATE_PROOF]
    assert ROOT_HASH in state_proof
    assert state_proof[ROOT_HASH]
    assert PROOF_NODES in state_proof
    assert state_proof[PROOF_NODES]
    assert MULTI_SIGNATURE in state_proof

    multi_sig = state_proof[MULTI_SIGNATURE]
    assert multi_sig
    assert multi_sig[MULTI_SIGNATURE_PARTICIPANTS]
    assert multi_sig[MULTI_SIGNATURE_SIGNATURE]
    assert MULTI_SIGNATURE_VALUE in multi_sig

    multi_sig_value = multi_sig[MULTI_SIGNATURE_VALUE]
    assert MULTI_SIGNATURE_VALUE_LEDGER_ID in multi_sig_value
    assert multi_sig_value[MULTI_SIGNATURE_VALUE_LEDGER_ID]
    assert MULTI_SIGNATURE_VALUE_STATE_ROOT in multi_sig_value
    assert multi_sig_value[MULTI_SIGNATURE_VALUE_STATE_ROOT]
    assert MULTI_SIGNATURE_VALUE_TXN_ROOT in multi_sig_value
    assert multi_sig_value[MULTI_SIGNATURE_VALUE_TXN_ROOT]
    assert MULTI_SIGNATURE_VALUE_POOL_STATE_ROOT in multi_sig_value
    assert multi_sig_value[MULTI_SIGNATURE_VALUE_POOL_STATE_ROOT]
    assert MULTI_SIGNATURE_VALUE_TIMESTAMP in multi_sig_value
    assert multi_sig_value[MULTI_SIGNATURE_VALUE_TIMESTAMP]
    if result[TYPE] == GET_REVOC_REG_DELTA:
        if STATE_PROOF_FROM in result[DATA] and result[DATA][STATE_PROOF_FROM]:
            reply_from = {DATA: result[DATA][VALUE][ACCUM_FROM],
                          STATE_PROOF: result[DATA][STATE_PROOF_FROM],
                          TYPE: result[TYPE],
                          f.SEQ_NO.nm: result[DATA][VALUE][ACCUM_FROM][f.SEQ_NO.nm],
                          TXN_TIME: result[DATA][VALUE][ACCUM_FROM][TXN_TIME]
                          }
            assert validate_proof(reply_from)
        reply_to = {DATA: result['data'][VALUE][ACCUM_TO],
                    STATE_PROOF: result[STATE_PROOF],
                    TYPE: result[TYPE],
                    f.SEQ_NO.nm: result[f.SEQ_NO.nm],
                    TXN_TIME: result[TXN_TIME]
                    }
        assert validate_proof(reply_to)
    else:
        assert validate_proof(result)
