# XECM

This python library calls the Opentext Extended ECM REST API.
The API documentation is available on [OpenText Developer](https://developer.opentext.com/ce/products/extendedecm)
A detailed documentation of this package is available [on GitHub](https://github.com/fitschgo/xecm).
Our Homepage is: [xECM SuccessFactors Knowledge](https://www.xecm-successfactors.com/xecm-knowledge.html)

# Quick start

Install "xecm":

```bash
pip install xecm
```

## Start using the xecm package
```python
import xecm
import logging

logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.INFO)  # use logging.ERROR to reduce logging

if __name__ == '__main__':
    deflogger = logging.getLogger("mylogger")
    cshost = 'http://otcs.phil.local'
    dshost = 'http://otds.phil.local'

    # get OTCSTicket with username and password
    csapi = xecm.CSRestAPI(xecm.LoginType.OTCS_TICKET, f'{cshost}/otcs/cs.exe', 'myuser', 's#cret', True, deflogger)

    # get OTDSTicket with username and password
    csapi = xecm.CSRestAPI(xecm.LoginType.OTDS_TICKET, dshost, 'myuser@partition', 's#cret', True, deflogger)

    # get OTDS Bearer Token with client id and client secret
    csapi = xecm.CSRestAPI(xecm.LoginType.OTDS_BEARER, dshost, 'oauth-user', 'gU5p8....4KZ', True, deflogger)

    # ...

    nodeId = 130480
    res = csapi.node_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name', 'type', 'type_name'], False, False, False)
    print(res)
    # {
    #   'properties': {'id': 130480, 'name': 'Bewerbung-Phil-Egger-2020.pdf', 'type': 144, 'type_name': 'Document'}, 
    #   'categories': [], 
    #   'permissions': {'owner': {}, 'group': {}, 'public': {}, 'custom': []}, 
    #   'classifications': []
    # }
```

## Available Logins: OTCSTicket, OTDSTicket or OTDS Bearer Token
```python
    # get OTCSTicket with username and password
    csapi = xecm.CSRestAPI(xecm.LoginType.OTCS_TICKET, cshost, 'myuser', 's#cret', deflogger)

    # get OTDSTicket with username and password
    csapi = xecm.CSRestAPI(xecm.LoginType.OTDS_TICKET, dshost, 'myuser@partition', 's#cret', deflogger)

    # get OTDS Bearer Token with client id and client secret
    csapi = xecm.CSRestAPI(xecm.LoginType.OTDS_BEARER, dshost, 'oauth-user', 'gU5p8....4KZ', deflogger)
```

## Node Functions (folder, document, ...)
```python
    # get node information - min -> load only some fields
    res = csapi.node_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name', 'type', 'type_name'], False, False, False)

    # get node information - max -> load all fields, incl. categories, incl. permissions, incl. classifications
    res = csapi.node_get(f'{cshost}/otcs/cs.exe', nodeId, [], True, True, True)

    # get sub nodes - min
    res = csapi.subnodes_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], False, False, False, 1)  # page 1 contains 200 sub items

    # get sub nodes - load categories
    res = csapi.subnodes_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], True, False, False, 1)  # page 1 contains 20 sub items

    # get sub nodes - load permissions
    res = csapi.subnodes_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], False, True, False, 1)  # page 1 contains 20 sub items

    # get sub nodes - load classifications
    res = csapi.subnodes_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], False, False, True, 1)  # page 1 contains 10 sub items

    # filter subnodes
    res = csapi.subnodes_filter(f'{cshost}/otcs/cs.exe', 30622, 'OTHCM_WS_Employee_Categories', False, True)

    # search nodes
    res = csapi.search(f'{cshost}/otcs/cs.exe', 'Documents', 0, baseFolderId, 1)

    # create new node - min
    res = csapi.node_create(f'{cshost}/otcs/cs.exe', parentId, 0, 'test', 'test', {}, {} )

    # create new node - with multiple metadata names
    res = csapi.node_create(f'{cshost}/cs/cs.exe', nodeId, 0, 'test', 'test', { 'en': 'test en', 'de': 'test de'}, { 'en': 'desc en', 'de': 'desc de'} )
    
    # update name and description of a node (folder, document, ...) - min
    res = csapi.node_update(f'{cshost}/cs/cs.exe', nodeId, 0, 'test1', 'desc1', {}, {}, {})

    # move node and apply categories
    cats = { '1279234_2': 'test' }
    res = csapi.node_update(f'{cshost}/cs/cs.exe', nodeId, newDestId, '', '', {}, {}, cats)

    # delete a node
    res = csapi.node_delete(f'{cshost}/cs/cs.exe', nodeId)
    
    # download a document into file system
    res = csapi.node_download_file(f'{cshost}/otcs/cs.exe', nodeId, '', '/home/fitsch/Downloads', 'test-download.pdf')

    # download a document as base64 string
    res = csapi.node_download_bytes(f'{cshost}/otcs/cs.exe', nodeId, '')
    # {'message', 'file_size', 'base64' }

    # upload a document from file system
    res = csapi.node_upload_file(f'{cshost}/otcs/cs.exe', nodeId, '/home/fitsch/Downloads', 'test-download.pdf', 'test-upload.pdf', { '30724_2': '2020-03-17' })

    # upload a document from byte array
    barr = open('/home/fitsch/Downloads/test-download.pdf', 'rb').read()
    res = csapi.node_upload_bytes(f'{cshost}/otcs/cs.exe', nodeId, barr, 'test-upload.pdf', {'30724_2': '2020-03-17'})

    # covert a Content Server path to a Node ID
    res = csapi.path_to_id(f'{cshost}/otcs/cs.exe', 'Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information')

    # get all volumes in Content Server
    res = csapi.volumes_get(f'{cshost}/otcs/cs.exe')
    # [
    # {
    #   'properties': 
    #   {
    #       'id': 2006, 
    #       'name': 'Content Server Categories'
    #   }
    # }, 
    # {
    #   'properties': 
    #   {
    #       'id': 2000, 
    #       'name': 'Enterprise'
    #   }
    # }, 
    # ...
    # ]

```

## Category Functions (Metadata)
```python
    # get node information and load categories
    res = csapi.node_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], True, False, False)

    # add category to node
    res = csapi.node_category_add(f'{cshost}/otcs/cs.exe', nodeId, { "category_id": 32133, "32133_2": "8000", "32133_39": ["test 1", "test 2"], "32133_33_1_34": "Org Unit 1", "32133_33_1_35": "Org Unit Desc 1", "32133_33_2_34": "Org Unit 2", "32133_33_2_35": "Org Unit Desc 2" } )

    # update category on a node
    res = csapi.node_category_update(f'{cshost}/otcs/cs.exe', nodeId, 32133, { "32133_2": "8000", "32133_39": ["test 1", "test 2"], "32133_33_1_34": "Org Unit 1", "32133_33_1_35": "Org Unit Desc 1", "32133_33_2_34": "Org Unit 2", "32133_33_2_35": "Org Unit Desc 2" } )
    
    # delete category from a node
    res = csapi.node_category_delete(f'{cshost}/otcs/cs.exe', nodeId, 32133)

    # read all category attributes - use i.e. path_to_id() to get cat_id
    res = csapi.category_get_mappings(f'{cshost}/otcs/cs.exe', cat_id)
    # {
    #   'main_name': 'Job Information', 
    #   'main_id': 32133, 
    #   'map_names': 
    #   {
    #       'Company Code': '32133_2', 
    #       'Company Code Description': '32133_3', 
    #       ...
    #   }, 
    #   'map_ids': 
    #   {
    #       '32133_2': 'Company Code', 
    #       '32133_3': 'Company Code Description', 
    #       ...
    #   }
    # }
    
    # get category information for a specific attribute
    res = csapi.category_attribute_id_get(f'{cshost}/otcs/cs.exe', 'Content Server Categories:SuccessFactors:OTHCM_WS_Employee_Categories:Personal Information', 'User ID')
    # {
    #   'category_id': 30643, 
    #   'category_name': 'Personal Information', 
    #   'attribute_key': '30643_26', 
    #   'attribute_name': 'User ID'
    # }
```

## Classification Functions
```python
    # get node information and load classifications
    res = csapi.node_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], False, False, True)

    # apply classifications to node
    res = csapi.node_classifications_apply(f'{cshost}/otcs/cs.exe', nodeId, False, [120571,120570])
    
    # same function to remove classification 120570 from node
    res = csapi.node_classifications_apply(f'{cshost}/otcs/cs.exe', nodeId, False, [120571])
```

## Permission Functions
```python
    # get node information and load permissions
    res = csapi.node_get(f'{cshost}/otcs/cs.exe', nodeId, ['id', 'name'], False, True, False)

    # apply owner permissions on node
    res = csapi.node_permissions_owner_apply(f'{cshost}/otcs/cs.exe', nodeId, { "permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"], "right_id": 1000 })

    # delete owner permission from node
    res = csapi.node_permissions_owner_delete(f'{cshost}/otcs/cs.exe', nodeId)

    # apply group permissions on node
    res = csapi.node_permissions_group_apply(f'{cshost}/otcs/cs.exe', nodeId, {"permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"], "right_id": 2001 })

    # delete group permission from node
    res = csapi.node_permissions_group_delete(f'{cshost}/otcs/cs.exe', nodeId)

    # apply public permissions on node
    res = csapi.node_permissions_public_apply(f'{cshost}/otcs/cs.exe', nodeId, {"permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"] })

    # delete public permission from node
    res = csapi.node_permissions_public_delete(f'{cshost}/otcs/cs.exe', nodeId)

    # apply a new custom permissions on node
    res = csapi.node_permissions_custom_apply(f'{cshost}/otcs/cs.exe', nodeId, [{"permissions":["see","see_contents"], "right_id": 1001 }])

    # update an existing custom permissions on node
    res = csapi.node_permissions_custom_update(f'{cshost}/otcs/cs.exe', nodeId, 2001, {"permissions":["delete","delete_versions","edit_attributes","edit_permissions","modify","reserve","see","see_contents"] })

    # delete a custom permissions from node
    res = csapi.node_permissions_custom_delete(f'{cshost}/otcs/cs.exe', nodeId, 1001)
```

## Smart Document Types Functions
```python
    # get all smart document types
    res = csapi.smartdoctypes_get_all(f'{cshost}/otcs/cs.exe')
    for smartdoctype in res:
        print(f"{smartdoctype['workspace_template_names']} - {smartdoctype['dataId']} - {smartdoctype['name']} --> {smartdoctype['classification_id']} - {smartdoctype['classification_name']}")

    # get rules of a smart document type
    smartDocTypeId = smartdoctype['dataId']
    res = csapi.smartdoctypes_rules_get(f'{cshost}/otcs/cs.exe', smartDocTypeId)
    for smartdoctype in res:
        print(f"{smartdoctype['template_name']} ({smartdoctype['template_id']}) - {smartdoctype['smartdocumenttype_id']} - RuleID: {smartdoctype['rule_id']} / DocGen: {smartdoctype['document_generation']} --> Classification: {smartdoctype['classification_id']} --> Location: {smartdoctype['location']}")

    # get rule detail
    ruleId = smartdoctype['rule_id']
    res = csapi.smartdoctype_rule_detail_get(f'{cshost}/otcs/cs.exe', ruleId)
    for rule_tab in res:
        print(f"tab: {rule_tab['bot_key']} - data: {rule_tab['data']}")

    # create smart document type under "Smart Document Types" root folder 6004 (id is different per system) -> see get_volumes() function
    res = csapi.smartdoctype_add(f'{cshost}/otcs/cs.exe', 6004, categoryId, 'smart doc test')

    # add workspace template to rule
    res = csapi.smartdoctype_workspacetemplate_add(f'{cshost}/otcs/cs.exe', smartDocTypeId, classificationId, templateId)
    # {
    #   'is_othcm_template': True, 
    #   'ok': True, 
    #   'rule_id': 11, 
    #   'statusCode': 200
    # }

    # add workspace template to rule -> get locationId with path_to_id() function
    location = csapi.path_to_id(f'{cshost}/otcs/cs.exe', 'Content Server Document Templates:SuccessFactors:Employee CHE:01 Entry Documents:110 Recruiting / Application')
    # {'id': 120603, 'name': '110 Recruiting / Application'}
    locationId = location.get('id', 0)
    res = csapi.smartdoctype_rule_context_save(f'{cshost}/otcs/cs.exe', ruleId, categoryId, locationId, 'update')
    # {
    #   'ok': True, 
    #   'statusCode': 200, 
    #   'updatedAttributeIds': [2], 
    #   'updatedAttributeNames': ['Date of Origin']
    # }

    # add 'mandatory' tab in rule
    res = csapi.smartdoctype_rule_mandatory_save(f'{cshost}/otcs/cs.exe', ruleId, True, 'add')

    # update 'mandatory' tab in rule
    res = csapi.smartdoctype_rule_mandatory_save(f'{cshost}/otcs/cs.exe', ruleId, False, 'update')

    # delete 'mandatory' tab in rule
    res = csapi.smartdoctype_rule_mandatory_delete(f'{cshost}/otcs/cs.exe', ruleId)

    # add 'document expiration' tab in rule
    res = csapi.smartdoctype_rule_documentexpiration_save(f'{cshost}/otcs/cs.exe', ruleId, True, 2, 0, 6, 'add')

    # update 'document expiration' tab in rule
    res = csapi.smartdoctype_rule_documentexpiration_save(f'{cshost}/otcs/cs.exe', ruleId, False, 2, 0, 4, 'update')

    # delete 'document expiration' tab in rule
    res = csapi.smartdoctype_rule_documentexpiration_delete(f'{cshost}/otcs/cs.exe', ruleId)

    # add 'document generation' tab in rule
    res = csapi.smartdoctype_rule_generatedocument_save(f'{cshost}/otcs/cs.exe', ruleId, True, 'add')

    # update 'document generation' tab in rule
    res = csapi.smartdoctype_rule_generatedocument_save(f'{cshost}/otcs/cs.exe', ruleId, False, 'update')

    # delete 'document generation' tab in rule
    res = csapi.smartdoctype_rule_generatedocument_delete(f'{cshost}/otcs/cs.exe', ruleId)

    # add 'allow upload' tab in rule
    res = csapi.smartdoctype_rule_allowupload_save(f'{cshost}/otcs/cs.exe', ruleId, [2001], 'add')

    # update 'allow upload' tab in rule
    res = csapi.smartdoctype_rule_allowupload_save(f'{cshost}/otcs/cs.exe', ruleId, [2001,120593], 'update')

    # delete 'allow upload' tab in rule
    res = csapi.smartdoctype_rule_allowupload_delete(f'{cshost}/otcs/cs.exe', ruleId)

    # add 'upload approval' tab in rule
    res = csapi.smartdoctype_rule_uploadapproval_save(f'{cshost}/otcs/cs.exe', ruleId, True, workflowMapId, [{'wfrole': 'Approver', 'member': 2001 }], 'add')

    # update 'allow upload' tab in rule
    res = csapi.smartdoctype_rule_uploadapproval_save(f'{cshost}/otcs/cs.exe', ruleId, True, workflowMapId, [{'wfrole': 'Approver', 'member': 120593 }], 'update')

    # delete 'allow upload' tab in rule
    res = csapi.smartdoctype_rule_uploadapproval_delete(f'{cshost}/otcs/cs.exe', ruleId)
```

## Business Workspace Functions
```python
    # get business workspace node id by business object type and business object id
    res = csapi.businessworkspace_search(f'{cshost}/otcs/cs.exe', 'SuccessFactors', 'sfsf:user', 'Z70080539', 1)

    # get customized smart document types for business workspace
    # bws_id from businessworkspace_search()
    res = csapi.businessworkspace_smartdoctypes_get(f'{cshost}/otcs/cs.exe', bws_id)
    # [{'classification_id': 120571, 'classification_name': 'Application Documents', 'classification_description': '', 'category_id': 6002, 'location': '122061:122063', 'document_generation': 0, 'required': 0, 'template_id': 120576}, ...]
    
    # get category definition for smart document type to be used for document upload into business workspace
    # bws_id from businessworkspace_search()
    # cat_id from businessworkspace_smartdoctypes_get()
    res = csapi.businessworkspace_categorydefinition_for_upload_get(f'{cshost}/otcs/cs.exe', bws_id, cat_id)

    # upload file using smart document type into business workspace
    res = csapi.businessworkspace_hr_upload_file(f'{cshost}/otcs/cs.exe', bws_id, '/home/fitsch/Downloads', 'test-download.pdf', 'application.pdf', class_dict['classification_id'], cat_id, cat_dict)
    
    ##### ########################## #####
    ##### snippet for upload process #####
    ##### ########################## #####
    res = csapi.businessworkspace_search(f'{cshost}/otcs/cs.exe', 'SuccessFactors', 'sfsf:user', 'Z70080539', 1)

    bws_id = -1
    class_name = 'Application Documents'
    class_dict = {}
    cat_id = -1
    cat_attr_date_of_origin = ''
    cat_dict = {}
    date_of_origin = datetime(2020, 5, 17)
    # res = {'results': [{'id': 122051, 'name': 'Employee Z70080539 Phil Egger', 'parent_id': 30648}, ... ], 'page_total': 1}
    if res and res.get('results', []) and len(res.get('results', [])) > 0:
        bws_id = res['results'][0].get('id', -1)

    if bws_id > 0:
        res = csapi.businessworkspace_smartdoctypes_get(f'{cshost}/otcs/cs.exe', bws_id)
        # res = [{'classification_id': 120571, 'classification_name': 'Application Documents', 'classification_description': '', 'category_id': 6002, 'location': '122061:122063', 'document_generation': 0, 'required': 0, 'template_id': 120576}, ... ]
        if res:
            for class_def in res:
                if class_def['classification_name'] == class_name:
                    class_dict = class_def
                    break

        if class_dict:
            # class_dict = {'classification_id': 120571, 'classification_name': 'Application Documents', 'classification_description': '', 'category_id': 6002, 'location': '122061:122063', 'document_generation': 0, 'required': 0, 'template_id': 120576}
            res = csapi.businessworkspace_categorydefinition_for_upload_get(f'{cshost}/otcs/cs.exe', bws_id, class_dict['category_id'])
            # res = [{'data': {'category_id': 6002, '6002_2': None}, 'options': {}, 'form': {}, 'schema': {'properties': {'category_id': {'readonly': False, 'required': False, 'title': 'Document Type Details', 'type': 'integer'}, '6002_2': {'readonly': False, 'required': False, 'title': 'Date of Origin', 'type': 'date'}}, 'type': 'object'}}]
            if res and len(res) > 0:
                if res[0].get('schema', {}) and res[0]['schema'].get('properties', {}):
                    # res[0]['schema']['properties'] = {'category_id': {'readonly': False, 'required': False, 'title': 'Document Type Details', 'type': 'integer'}, '6002_2': {'readonly': False, 'required': False, 'title': 'Date of Origin', 'type': 'date'}}
                    cat_id = class_dict['category_id']
                    for p in res[0]['schema']['properties']:
                        if str(cat_id) in p and res[0]['schema']['properties'][p].get('type', '') == 'date' and 'Origin' in res[0]['schema']['properties'][p].get('title', ''):
                            cat_attr_date_of_origin = p
                            break

            if cat_id > 0 and cat_attr_date_of_origin:
                cat_dict =  { cat_attr_date_of_origin: date_of_origin.isoformat() }
            else:
                deflogger.info(f'Date Of Origin not found in Category {class_dict['category_id']} for Workspace {bws_id}')

            try:
                res = csapi.businessworkspace_hr_upload_file(f'{cshost}/otcs/cs.exe', bws_id, '/home/fitsch/Downloads', 'test-download.pdf', 'application.pdf', class_dict['classification_id'], cat_id, cat_dict)
                if res > 0:
                    deflogger.info(f'File successfully uploaded - {res}')
                else:
                    raise Exception(f'Invalid Node ID returned: {res}')
            except Exception as innerErr:
                deflogger.error(f'File failed to upload {innerErr}')
        else:
            deflogger.error(f'Classification Definition not found for {class_name} in Workspace {bws_id}')

```

## WebReport Functions
```python
    # call web report by nickname using parameters
    res = csapi.webreport_nickname_call(f'{cshost}/otcs/cs.exe', 'WR_API_Test', {'p_name': 'name', 'p_desc': 'description'})

    # call web report by node id using parameters
    res = csapi.webreport_nodeid_call(f'{cshost}/otcs/cs.exe', wr_id, {'p_name': 'name', 'p_desc': 'description'})
```

## Server Information Functions
```python
    # ping Content Server
    res = csapi.ping(f'{cshost}/otcs/cs.exe')

    # get server info (version, metadata languages, ...)
    res = csapi.server_info(f'{cshost}/otcs/cs.exe')
    print(f"Version: {res['server']['version']}")
    print('Metadata Languages:')
    for lang in res['server']['metadata_languages']:
        print(f"{lang['language_code']} - {lang['display_name']}")
```

## Basic API Functions - in case that something is not available in this class
```python
    # GET API Call
    res = csapi.call_get(f'{cshost}/otcs/cs.exe/api/v1/nodes/2000/classifications')

    # POST API Call using form-url-encoded -> i.e. do fancy search
    res = csapi.call_post_form_url_encoded(f'{cshost}/otcs/cs.exe/api/v2/search', { 'body': json.dumps({ 'where': 'OTName: "Personal Information" and OTSubType: 131 and OTLocation: 2006' })})

    # POST API Call using form-data -> can be used to upload files
    data = { 'type': 144, 'parent_id': parent_id, 'name': remote_filename }
    params = { 'body' : json.dumps(data) }
    files = {'file': (remote_filename, open(os.path.join(local_folder, local_filename), 'rb'), 'application/octet-stream')}
    res = csapi.call_post_form_data(f'{cshost}/otcs/cs.exe/api/v2/nodes', params, files)

    # PUT API Call
    params = {'body': json.dumps(category)}
    res = self.call_put(f'{cshost}/otcs/cs.exe/api/v2/nodes/{node_id}/categories/{category_id}', params)

    # DELETE API Call
    res = self.call_delete(f'{cshost}/otcs/cs.exe/api/v2/nodes/{node_id}/categories/{category_id}')
```

# Disclaimer

Copyright © 2025 by Philipp Egger, All Rights Reserved. The copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.