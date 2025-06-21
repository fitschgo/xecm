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
    
    # get OTCSTicket with username and password
    login = xecm.XECMLogin(xecm.LoginType.OTCS_TICKET, 'http://otcs.phil.local/otcs/cs.exe', 'myuser', 's#cret', deflogger)

    # get OTDSTicket with username and password
    login = xecm.XECMLogin(xecm.LoginType.OTDS_TICKET, 'http://otds.phil.local', 'myuser@partition', 's#cret', deflogger)

    # get OTDS Bearer Token with client id and client secret
    login = xecm.XECMLogin(xecm.LoginType.OTDS_BEARER, 'http://otds.phil.local', 'oauth-user', 'gU5p8....4KZ', deflogger)

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