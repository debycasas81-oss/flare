import logging
import platform
import sys
import time
import re
from datetime import timedelta
from html import escape
from urllib.parse import unquote, quote

from func_timeout import FunctionTimedOut, func_timeout
from selenium.common import TimeoutException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.expected_conditions import (
    presence_of_element_located, staleness_of, title_is)
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.support.wait import WebDriverWait

import utils
from dtos import (STATUS_ERROR, STATUS_OK, ChallengeResolutionResultT,
                  ChallengeResolutionT, HealthResponse, IndexResponse,
                  V1RequestBase, V1ResponseBase)
from sessions import SessionsStorage

CSRF_PATTERN = r"name=\"csrfToken\" value=\"([^\"]+)\""
ACCESS_DENIED_TITLES = [
    # Cloudflare
    'Access denied',
    # Cloudflare http://bitturk.net/ Firefox
    'Attention Required! | Cloudflare'
]
ACCESS_DENIED_SELECTORS = [
    # Cloudflare
    'div.cf-error-title span.cf-code-label span',
    # Cloudflare http://bitturk.net/ Firefox
    '#cf-error-details div.cf-error-overview h1'
]
CHALLENGE_TITLES = [
    # Cloudflare (English)
    'Just a moment...',
    # Cloudflare (Portuguese)
    'Um momento…',
    'Um momento...',
    # Cloudflare (Spanish)
    'Un momento...',
    # Cloudflare (French)
    'Un instant...',
    # Cloudflare (German)
    'Einen Moment...',
    # DDoS-GUARD
    'DDoS-Guard'
]
CHALLENGE_SELECTORS = [
    # Cloudflare
    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',
    # Custom CloudFlare for EbookParadijs, Film-Paleis, MuziekFabriek and Puur-Hollands
    'td.info #js_info',
    # Fairlane / pararius.com
    'div.vc div.text-box h2'
]

TURNSTILE_SELECTORS = [
    "input[name='cf-turnstile-response']"
]

SHORT_TIMEOUT = 1
SESSIONS_STORAGE = SessionsStorage()


def test_browser_installation():
    logging.info("Testing web browser installation...")
    logging.info("Platform: " + platform.platform())

    chrome_exe_path = utils.get_chrome_exe_path()
    if chrome_exe_path is None:
        logging.error("Chrome / Chromium web browser not installed!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium path: " + chrome_exe_path)

    chrome_major_version = utils.get_chrome_major_version()
    if chrome_major_version == '':
        logging.error("Chrome / Chromium version not detected!")
        sys.exit(1)
    else:
        logging.info("Chrome / Chromium major version: " + chrome_major_version)

    logging.info("Launching web browser...")
    user_agent = utils.get_user_agent()
    logging.info("FlareSolverr User-Agent: " + user_agent)
    logging.info("Test successful!")


def index_endpoint() -> IndexResponse:
    res = IndexResponse({})
    res.msg = "FlareSolverr is ready!"
    res.version = utils.get_flaresolverr_version()
    res.userAgent = utils.get_user_agent()
    return res


def health_endpoint() -> HealthResponse:
    res = HealthResponse({})
    res.status = STATUS_OK
    return res


def controller_v1_endpoint(req: V1RequestBase) -> V1ResponseBase:
    start_ts = int(time.time() * 1000)
    logging.info(f"Incoming request => POST /v1 body: {utils.object_to_dict(req)}")
    res: V1ResponseBase
    try:
        res = _controller_v1_handler(req)
    except Exception as e:
        res = V1ResponseBase({})
        res.__error_500__ = True
        res.status = STATUS_ERROR
        res.message = "Error: " + str(e)
        logging.error(res.message)

    res.startTimestamp = start_ts
    res.endTimestamp = int(time.time() * 1000)
    res.version = utils.get_flaresolverr_version()
    logging.debug(f"Response => POST /v1 body: {utils.object_to_dict(res)}")
    logging.info(f"Response in {(res.endTimestamp - res.startTimestamp) / 1000} s")
    return res


def _controller_v1_handler(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.cmd is None:
        raise Exception("Request parameter 'cmd' is mandatory.")
    if req.headers is not None:
        logging.warning("Request parameter 'headers' was removed in FlareSolverr v2.")
    if req.userAgent is not None:
        logging.warning("Request parameter 'userAgent' was removed in FlareSolverr v2.")

    # set default values
    if req.maxTimeout is None or int(req.maxTimeout) < 1:
        req.maxTimeout = 60000

    # execute the command
    res: V1ResponseBase
    if req.cmd == 'sessions.create':
        res = _cmd_sessions_create(req)
    elif req.cmd == 'sessions.list':
        res = _cmd_sessions_list(req)
    elif req.cmd == 'sessions.destroy':
        res = _cmd_sessions_destroy(req)
    elif req.cmd == 'request.get':
        res = _cmd_request_get(req)
    elif req.cmd == 'request.post':
        res = _cmd_request_post(req)
    else:
        raise Exception(f"Request parameter 'cmd' = '{req.cmd}' is invalid.")

    return res


def _cmd_request_get(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.url is None:
        raise Exception("Request parameter 'url' is mandatory in 'request.get' command.")
    if req.postData is not None:
        raise Exception("Cannot use 'postBody' when sending a GET request.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'GET')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_request_post(req: V1RequestBase) -> V1ResponseBase:
    # do some validations
    if req.postData is None:
        raise Exception("Request parameter 'postData' is mandatory in 'request.post' command.")
    if req.returnRawHtml is not None:
        logging.warning("Request parameter 'returnRawHtml' was removed in FlareSolverr v2.")
    if req.download is not None:
        logging.warning("Request parameter 'download' was removed in FlareSolverr v2.")

    challenge_res = _resolve_challenge(req, 'POST')
    res = V1ResponseBase({})
    res.status = challenge_res.status
    res.message = challenge_res.message
    res.solution = challenge_res.result
    return res


def _cmd_sessions_create(req: V1RequestBase) -> V1ResponseBase:
    logging.debug("Creating new session...")

    session, fresh = SESSIONS_STORAGE.create(session_id=req.session, proxy=req.proxy)
    session_id = session.session_id

    if not fresh:
        return V1ResponseBase({
            "status": STATUS_OK,
            "message": "Session already exists.",
            "session": session_id
        })

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "Session created successfully.",
        "session": session_id
    })


def _cmd_sessions_list(req: V1RequestBase) -> V1ResponseBase:
    session_ids = SESSIONS_STORAGE.session_ids()

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "",
        "sessions": session_ids
    })


def _cmd_sessions_destroy(req: V1RequestBase) -> V1ResponseBase:
    session_id = req.session
    existed = SESSIONS_STORAGE.destroy(session_id)

    if not existed:
        raise Exception("The session doesn't exist.")

    return V1ResponseBase({
        "status": STATUS_OK,
        "message": "The session has been removed."
    })


def _resolve_challenge(req: V1RequestBase, method: str) -> ChallengeResolutionT:
    timeout = int(req.maxTimeout) / 1000
    driver = None
    try:
        if req.session:
            session_id = req.session
            ttl = timedelta(minutes=req.session_ttl_minutes) if req.session_ttl_minutes else None
            session, fresh = SESSIONS_STORAGE.get(session_id, ttl)

            if fresh:
                logging.debug(f"new session created to perform the request (session_id={session_id})")
            else:
                logging.debug(f"existing session is used to perform the request (session_id={session_id}, "
                              f"lifetime={str(session.lifetime())}, ttl={str(ttl)})")

            driver = session.driver
        else:
            driver = utils.get_webdriver(req.proxy)
            logging.debug('New instance of webdriver has been created to perform the request')
        return func_timeout(timeout, _evil_logic, (req, driver, method))
    except FunctionTimedOut:
        raise Exception(f'Error solving the challenge. Timeout after {timeout} seconds.')
    except Exception as e:
        raise Exception('Error solving the challenge. ' + str(e).replace('\n', '\\n'))
    finally:
        if not req.session and driver is not None:
            if utils.PLATFORM_VERSION == "nt":
                driver.close()
            driver.quit()
            logging.debug('A used instance of webdriver has been destroyed')

# def click_verify(driver: WebDriver):
#     try:
#         logging.debug("Try to find the Cloudflare verify checkbox...")
#         actions = ActionChains(driver)
#         actions.pause(5).send_keys(Keys.TAB).pause(1).send_keys(Keys.SPACE).perform()
#         logging.debug("Cloudflare verify checkbox found and clicked!")
#     except Exception:
#         logging.debug("Cloudflare verify checkbox not found on the page.")
#     finally:
#         driver.switch_to.default_content()

#     try:
#         logging.debug("Try to find the Cloudflare 'Verify you are human' button...")
#         button = driver.find_element(
#             by=By.XPATH,
#             value="//input[@type='button' and @value='Verify you are human']",
#         )
#         if button:
#             actions = ActionChains(driver)
#             actions.move_to_element_with_offset(button, 5, 7)
#             actions.click(button)
#             actions.perform()
#             logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
#     except Exception:
#         logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

#     time.sleep(2)

def click_verify_upstream(driver: WebDriver, num_tabs: int = 1):
    """Upstream click_verify with tab-based navigation (used by _get_turnstile_token)"""
    try:
        logging.debug("Try to find the Cloudflare verify checkbox...")
        actions = ActionChains(driver)
        actions.pause(5)
        for _ in range(num_tabs):
            actions.send_keys(Keys.TAB).pause(0.1)
        actions.pause(1)
        actions.send_keys(Keys.SPACE).perform()

        logging.debug(f"Cloudflare verify checkbox clicked after {num_tabs} tabs!")
    except Exception:
        logging.debug("Cloudflare verify checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()

    try:
        logging.debug("Try to find the Cloudflare 'Verify you are human' button...")
        button = driver.find_element(
            by=By.XPATH,
            value="//input[@type='button' and @value='Verify you are human']",
        )
        if button:
            actions = ActionChains(driver)
            actions.move_to_element_with_offset(button, 5, 7)
            actions.click(button)
            actions.perform()
            logging.debug("The Cloudflare 'Verify you are human' button found and clicked!")
    except Exception:
        logging.debug("The Cloudflare 'Verify you are human' button not found on the page.")

    time.sleep(2)

def _get_turnstile_wait_budget_seconds(max_timeout_ms: int) -> float:
    max_timeout_seconds = max_timeout_ms / 1000.0
    return min(max(15.0, max_timeout_seconds / 2.0), max_timeout_seconds)


def _get_turnstile_token(driver: WebDriver, tabs: int, max_timeout_ms: int):
    current_value = None
    try:
        token_input = driver.find_element(By.CSS_SELECTOR, "input[name='cf-turnstile-response']")
        current_value = token_input.get_attribute("value")
    except Exception:
        pass

    wait_budget_seconds = _get_turnstile_wait_budget_seconds(max_timeout_ms)
    deadline = time.monotonic() + wait_budget_seconds
    attempt = 0

    while time.monotonic() < deadline:
        attempt = attempt + 1
        click_verify_upstream(driver, num_tabs=tabs)
        try:
            token_input = driver.find_element(By.CSS_SELECTOR, "input[name='cf-turnstile-response']")
            turnstile_token = token_input.get_attribute("value")
            if turnstile_token and turnstile_token != current_value:
                logging.info(f"Turnstile token: {turnstile_token}")
                return turnstile_token
        except Exception:
            pass
        logging.debug("Failed to extract token, possibly click failed or element stale")

        # reset focus
        driver.execute_script("""
            let el = document.createElement('button');
            el.style.position='fixed';
            el.style.top='0';
            el.style.left='0';
            document.body.prepend(el);
            el.focus();
        """)
        if time.monotonic() < deadline:
            time.sleep(min(1.0, max(0.5, (deadline - time.monotonic()) / 2.0)))

    logging.warning(
        f"Timed out after {wait_budget_seconds:.1f}s waiting for Turnstile token after {attempt} attempts"
    )
    return None

def _resolve_turnstile_captcha(req: V1RequestBase, driver: WebDriver):
    turnstile_token = None
    if req.tabs_till_verify is not None:
        logging.debug(f'Navigating to... {req.url} in order to pass the turnstile challenge')
        driver.get(req.url)

        turnstile_challenge_found = False
        for selector in TURNSTILE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                turnstile_challenge_found = True
                logging.info("Turnstile challenge detected. Selector found: " + selector)
                break
        if turnstile_challenge_found:
            turnstile_token = _get_turnstile_token(
                driver=driver,
                tabs=req.tabs_till_verify,
                max_timeout_ms=int(req.maxTimeout) if req.maxTimeout is not None else 60000,
            )
        else:
            logging.debug(f'Turnstile challenge not found')
    return turnstile_token

def click_verify(driver: WebDriver):
    """Custom click_verify with grid/offset logic (used by Postman challenge loop)"""
    try:
        logging.debug("Try to find the Cloudflare Turnstile checkbox...")

        button = driver.find_element(By.CSS_SELECTOR, "div[style*=\"display: grid;\"]")
        width = button.size['width'] / 2;
        height = button.size['height'] / 2;
        coordinateX = height - width;
        coordinateY = 0;

        actions = ActionChains(driver)
        actions.move_to_element_with_offset(button, coordinateX, coordinateY)
        actions.click()
        actions.perform()

        logging.debug("Cloudflare Turnstile checkbox found and clicked!")
    except Exception:
        logging.debug("Cloudflare Turnstile checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()

def click_turnstile(driver: WebDriver):
    try:
        logging.debug("Try to find the Cloudflare Turnstile checkbox...")

        driver.execute_script("document.querySelector(\"div:has(> input[name=\\\"cf-turnstile-response\\\"])\").style = \"width: 60px;\"")

        button = driver.find_element(By.CSS_SELECTOR, "div:has(> input[name=\"cf-turnstile-response\"])")
        actions = ActionChains(driver)
        actions.click(button)
        actions.perform()

        logging.debug("Cloudflare Turnstile checkbox found and clicked!")
    except Exception:
        logging.debug("Cloudflare Turnstile checkbox not found on the page.")
    finally:
        driver.switch_to.default_content()


def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:
    res = ChallengeResolutionT({})
    res.status = STATUS_OK
    res.message = ""

    # optionally block resources like images/css/fonts using CDP
    disable_media = utils.get_config_disable_media()
    if req.disableMedia is not None:
        disable_media = req.disableMedia
    if disable_media:
        block_urls = [
            # Images
            "*.png", "*.jpg", "*.jpeg", "*.gif", "*.webp", "*.bmp", "*.svg", "*.ico",
            "*.PNG", "*.JPG", "*.JPEG", "*.GIF", "*.WEBP", "*.BMP", "*.SVG", "*.ICO",
            "*.tiff", "*.tif", "*.jpe", "*.apng", "*.avif", "*.heic", "*.heif",
            "*.TIFF", "*.TIF", "*.JPE", "*.APNG", "*.AVIF", "*.HEIC", "*.HEIF",
            # Stylesheets
            "*.css",
            "*.CSS",
            # Fonts
            "*.woff", "*.woff2", "*.ttf", "*.otf", "*.eot",
            "*.WOFF", "*.WOFF2", "*.TTF", "*.OTF", "*.EOT"
        ]
        try:
            logging.debug("Network.setBlockedURLs: %s", block_urls)
            driver.execute_cdp_cmd("Network.enable", {})
            driver.execute_cdp_cmd("Network.setBlockedURLs", {"urls": block_urls})
        except Exception:
            # if CDP commands are not available or fail, ignore and continue
            logging.debug("Network.setBlockedURLs failed or unsupported on this webdriver")

    # navigate to the page
    logging.debug(f"Navigating to... {req.url}")
    turnstile_token = None

    if method == "POST":
        _post_request(req, driver)
    else:
        if req.tabs_till_verify is None:
            driver.get(req.url)
        else:
            turnstile_token = _resolve_turnstile_captcha(req, driver)

    # set cookies if required
    if req.cookies is not None and len(req.cookies) > 0:
        logging.debug(f'Setting cookies...')
        for cookie in req.cookies:
            driver.delete_cookie(cookie['name'])
            driver.add_cookie(cookie)
        # reload the page
        if method == 'POST':
            _post_request(req, driver)
        else:
            driver.get(req.url)

    # wait for the page
    if utils.get_config_log_html():
        logging.debug(f"Response HTML:\n{driver.page_source}")
    html_element = driver.find_element(By.TAG_NAME, "html")
    page_title = driver.title

    # find access denied titles
    for title in ACCESS_DENIED_TITLES:
        if page_title.startswith(title):
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')
    # find access denied selectors
    for selector in ACCESS_DENIED_SELECTORS:
        found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
        if len(found_elements) > 0:
            raise Exception('Cloudflare has blocked this request. '
                            'Probably your IP is banned for this site, check in your web browser.')

    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break
    if not challenge_found:
        # language-agnostic detection: the new interstitial markup uses random
        # IDs, so match on the Cloudflare challenge bootstrap instead
        page_source = driver.page_source
        if '_cf_chl_opt' in page_source or '/cdn-cgi/challenge-platform/' in page_source:
            challenge_found = True
            logging.info("Challenge detected. Cloudflare challenge bootstrap found.")

    attempt = 0
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1
                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug("Waiting for title (attempt " + str(attempt) + "): " + title)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(title_is(title))

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    logging.debug("Waiting for selector (attempt " + str(attempt) + "): " + selector)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))

                # all elements not found
                break

            except TimeoutException:
                logging.debug("Timeout waiting for selector")

                click_verify(driver)

                # update the html (cloudflare reloads the page every 5 s)
                html_element = driver.find_element(By.TAG_NAME, "html")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, SHORT_TIMEOUT).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if "https://identity.getpostman.com/login" in driver.current_url:
        csrfMatch = re.search(CSRF_PATTERN, driver.page_source)

        if csrfMatch:
            challenge_res.csrf = csrfMatch.group(1)

        # wait up to 10s for the Turnstile input to appear
        try:
            WebDriverWait(driver, 10).until(
                presence_of_element_located((By.XPATH, "//input[@type='hidden' and @name='cf-turnstile-response']"))
            )
            logging.debug("Turnstile input appeared in DOM")
        except TimeoutException:
            logging.debug("Turnstile input did not appear within 10s")

    attempt = 0
    captcha = None
    while True:
        try:
            attempt = attempt + 1
            captcha_element = driver.find_elements(
                by=By.XPATH,
                value="//input[@type='hidden' and @name='cf-turnstile-response']",
            )
            if not captcha_element:
                logging.debug("Turnstile input not found on page, skipping captcha extraction")
                break
            captcha = captcha_element[0].get_attribute("value")
            if not captcha or captcha == "":
                logging.debug("Waiting for captcha result (attempt " + str(attempt) + ")")
                click_turnstile(driver)
                time.sleep(2)
                raise TimeoutException()
            break
        except TimeoutException:
            logging.debug("Timeout waiting for captcha result")
            if attempt > 10:
                logging.warning("Max attempts reached waiting for turnstile token")
                break

    if captcha:
        challenge_res.captcha = captcha

        # Submit login form natively so Cloudflare sees a real browser interaction
        try:
            username_val = req.credentials.split(":", 1)[0] if req.credentials else None
            password_val = req.credentials.split(":", 1)[1] if req.credentials and ":" in req.credentials else None

            if username_val and password_val:
                login_url = driver.current_url
                logging.info(f"[LOGIN] Submitting form at: {login_url}")

                # clear seleniumwire request log before submitting
                del driver.requests

                # fill username and password fields and submit via JS
                # values are passed as arguments (not string-interpolated) so that
                # credentials containing quotes/backslashes/newlines can't break the
                # script or inject JS
                driver.execute_script("""
                    const username = arguments[0], password = arguments[1];
                    const emailInput = document.querySelector('input[name="username"], input[type="email"], input[id="username"]');
                    const passInput  = document.querySelector('input[name="password"], input[type="password"], input[id="password"]');
                    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set;
                    if (emailInput) {
                        nativeInputValueSetter.call(emailInput, username);
                        emailInput.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                    if (passInput) {
                        nativeInputValueSetter.call(passInput, password);
                        passInput.dispatchEvent(new Event('input', { bubbles: true }));
                    }
                    const btn = document.querySelector('button[type="submit"], input[type="submit"]');
                    if (btn) btn.click();
                """, username_val, password_val)

                # wait for the login POST response via seleniumwire
                import time as _time
                from urllib.parse import urlparse
                deadline = _time.time() + 15
                login_response_body = None
                login_response_status = None
                while _time.time() < deadline:
                    for req_sw in driver.requests:
                        _parsed = urlparse(req_sw.url)
                        _is_login_host = _parsed.netloc == 'identity.getpostman.com'
                        _is_login_path = _parsed.path == '/login'
                        if _is_login_host and _is_login_path and req_sw.method == 'POST' and req_sw.response:
                            login_response_status = req_sw.response.status_code
                            try:
                                from seleniumwire.utils import decode as sw_decode
                                body_bytes = sw_decode(
                                    req_sw.response.body,
                                    req_sw.response.headers.get('Content-Encoding', 'identity')
                                )
                                login_response_body = body_bytes.decode('utf-8', errors='replace')
                            except Exception:
                                login_response_body = req_sw.response.body.decode('utf-8', errors='replace') if req_sw.response.body else ''
                            break
                    if login_response_status is not None:
                        break
                    _time.sleep(0.3)

                # wait a moment for redirect or error to settle after POST
                _time.sleep(1.5)

                # determine success by checking if the browser landed on *.postman.co
                # (not just left the /login path — verify-account, 2fa, etc. are still failures)
                _final_url = driver.current_url
                _still_on_login = 'identity.getpostman.com' in _final_url

                # try to read an error message from the DOM when login failed
                _error_msg = None
                if _still_on_login:
                    try:
                        _err_el = driver.find_elements(
                            By.CSS_SELECTOR,
                            '[data-testid="error-message"], .error-message, '
                            '[class*="error"], [class*="alert"], [role="alert"]'
                        )
                        for _el in _err_el:
                            _txt = _el.text.strip()
                            if _txt:
                                # use only the first non-empty line as the error message
                                _error_msg = next((l.strip() for l in _txt.splitlines() if l.strip()), _txt)
                                break
                    except Exception:
                        pass

                _login_success = not _still_on_login

                # Postman's login endpoint returns 200 with empty body on success —
                # fall back to page_source so the caller gets the post-login page content
                if not login_response_body:
                    login_response_body = driver.page_source

                logging.info(f"[LOGIN] form status: {login_response_status}")
                logging.info(f"[LOGIN] current url after login: {_final_url}")
                logging.info(f"[LOGIN] success: {_login_success} | error: {_error_msg}")
                challenge_res.loginResponse = {
                    "status": login_response_status or 0,
                    "body": login_response_body or "",
                    "success": _login_success,
                    "error": _error_msg or ("" if _login_success else f"Login failed: redirected to {_final_url}"),
                    "finalUrl": _final_url,
                }
        except Exception as e:
            logging.info(f"[LOGIN] form submit error: {e}")

    if "identity.getpostman.com" not in driver.current_url:
        # Só re-captura cookies/URL quando o browser saiu de identity.getpostman.com.
        # Verify-account, 2fa, etc. ainda estão em identity.getpostman.com → não re-captura.
        # Agora o browser está em *.postman.co e tem postman.sid para .postman.co.
        challenge_res.cookies = driver.get_cookies()
        challenge_res.url = driver.current_url

        if not req.returnOnlyCookies:
            challenge_res.headers = {}  # todo: fix, selenium not provides this info

            if req.waitInSeconds and req.waitInSeconds > 0:
                logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
                time.sleep(req.waitInSeconds)

            challenge_res.response = driver.page_source

            # Extrai team ID numérico da page source (para x-entity-team-id no WS proxy)
            _team_id_val = None
            _page_src = challenge_res.response or ""
            for _pat in [
                r'"entityId"\s*:\s*(\d{6,})',
                r'"teamId"\s*:\s*(\d{6,})',
                r'"team_id"\s*:\s*(\d{6,})',
                r'entity[_\-]team[_\-]id["\s:]+(\d{6,})',
                r'"id"\s*:\s*(\d{6,})\s*,\s*"teamType"',
            ]:
                _m = re.search(_pat, _page_src)
                if _m:
                    _team_id_val = _m.group(1)
                    logging.info(f"[LOGIN] teamId extracted: {_team_id_val}")
                    break
            if _team_id_val and isinstance(challenge_res.loginResponse, dict):
                challenge_res.loginResponse["teamId"] = _team_id_val

        if req.returnScreenshot:
            challenge_res.screenshot = driver.get_screenshot_as_base64()

    res.result = challenge_res
    return res


def _post_request(req: V1RequestBase, driver: WebDriver):
    post_form = f'<form id="hackForm" action="{req.url}" method="POST">'
    query_string = req.postData if req.postData and req.postData[0] != '?' else req.postData[1:] if req.postData else ''
    pairs = query_string.split('&')
    for pair in pairs:
        parts = pair.split('=', 1)
        # noinspection PyBroadException
        try:
            name = unquote(parts[0])
        except Exception:
            name = parts[0]
        if name == 'submit':
            continue
        # noinspection PyBroadException
        try:
            value = unquote(parts[1]) if len(parts) > 1 else ''
        except Exception:
            value = parts[1] if len(parts) > 1 else ''
        # Protection of " character, for syntax
        value=value.replace('"','&quot;')
        post_form += f'<input type="text" name="{escape(quote(name))}" value="{escape(quote(value))}"><br>'
    post_form += '</form>'
    html_content = f"""
        <!DOCTYPE html>
        <html>
        <body>
            {post_form}
            <script>document.getElementById('hackForm').submit();</script>
        </body>
        </html>"""
    driver.get("data:text/html;charset=utf-8,{html_content}".format(html_content=html_content))
