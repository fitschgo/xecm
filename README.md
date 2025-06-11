# XECM

This python library calls the Opentext Extended ECM REST API.
The API documentation is available on [OpenText Developer](https://developer.opentext.com/ce/products/extendedecm)
A detailed documentation of this package is available [on GitHub](https://fitschgo.github.io/xecm/).

# Quick start

Install "xecm":

```bash
pip install xecm
```

## Start using the xecm package
```python
import xecm

if __name__ == '__main__':
    login = xecm.XECMLogin('', '', '', '', '', '')

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