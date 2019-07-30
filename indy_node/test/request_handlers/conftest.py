import pytest
from indy_common.constants import SCHEMA, REVOC_REG_DEF, CRED_DEF_ID, REVOC_TYPE, TAG

from indy_node.persistence.idr_cache import IdrCache
from indy_node.server.request_handlers.domain_req_handlers.revoc_reg_def_handler import RevocRegDefHandler
from indy_node.server.request_handlers.domain_req_handlers.schema_handler import SchemaHandler
from indy_node.test.request_handlers.helper import add_to_idr
from plenum.common.constants import KeyValueStorageType
from plenum.common.request import Request
from plenum.common.util import randomString
from storage.helper import initKeyValueStorage


@pytest.fixture(scope="function", params=["no_endorser", "with_endorser"])
def endorser(request):
    if request.param == "no_endorser":
        return None
    return "5gC6mJq5MoGPwubtU8F5Qc"


@pytest.fixture(scope="module")
def idr_cache(tconf, tdir):
    name = 'name'
    idr_cache = IdrCache(name,
                         initKeyValueStorage(KeyValueStorageType.Rocksdb,
                                             tdir,
                                             tconf.idrCacheDbName,
                                             db_config=tconf.db_idr_cache_db_config))
    return idr_cache


@pytest.fixture(scope="module")
def schema_handler(db_manager, write_auth_req_validator):
    return SchemaHandler(db_manager, write_auth_req_validator)


@pytest.fixture(scope="function")
def schema_request(endorser):
    return Request(identifier=randomString(),
                   reqId=5,
                   signature="sig",
                   operation={'type': SCHEMA,
                              'data': {
                                  'version': '1.0',
                                  'name': 'Degree',
                                  'attr_names': ['last_name',
                                                 'first_name', ]
                              }},
                   endorser=endorser)


@pytest.fixture(scope="module")
def revoc_reg_def_handler(db_manager, write_auth_req_validator):
    return RevocRegDefHandler(db_manager, write_auth_req_validator)


@pytest.fixture(scope="function")
def revoc_reg_def_request(endorser):
    return Request(identifier=randomString(),
                   reqId=5,
                   signature="sig",
                   operation={'type': REVOC_REG_DEF,
                              CRED_DEF_ID: "credDefId",
                              REVOC_TYPE: randomString(),
                              TAG: randomString(),
                              },
                   endorser=endorser)


@pytest.fixture(scope="module")
def creator(db_manager):
    identifier = randomString()
    idr = db_manager.idr_cache
    add_to_idr(idr, identifier, None)
    return identifier
