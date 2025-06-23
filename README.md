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
    csapi = xecm.CSRestAPI(xecm.LoginType.OTCS_TICKET, cshost, 'myuser', 's#cret', deflogger)

    # get OTDSTicket with username and password
    csapi = xecm.CSRestAPI(xecm.LoginType.OTDS_TICKET, dshost, 'myuser@partition', 's#cret', deflogger)

    # get OTDS Bearer Token with client id and client secret
    csapi = xecm.CSRestAPI(xecm.LoginType.OTDS_BEARER, dshost, 'oauth-user', 'gU5p8....4KZ', deflogger)

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


# Disclaimer

Copyright © 2025 by Philipp Egger, All Rights Reserved. The copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.