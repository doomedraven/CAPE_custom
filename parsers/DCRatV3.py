from contextlib import suppress
import logging
import base64
import gzip
import json

# DCRat CAPE Config-Extractor
# DCRatV3 Base64-ZIP-ConfigStrings
# Claudio Wayne
# https://github.com/ClaudioWayne/
# V1.2
# 18-02-2025 - V1.0 - Inital
# 19-02-2025 - V1.1 - Additional Config
# 19-03-2025 - V1.2 - Added URL-Path decryption

try:
    from cape_parsers.utils.strings import extract_strings
except ImportError as e:
    print(f"Problem to import extract_strings: {e}")

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)

def decompress(gstring):
    try:
        return gzip.decompress(gstring)
    except Exception as e:
        logger.debug(e)
    return

def decode_b64(b64string):
    try:
        return base64.b64decode(b64string)
    except Exception as e:
        logger.debug(e)
    return

def revert_string(revstring):
  return revstring[::-1]

def find_conf(strings):

    conf = {}
    replace_strings = []

    for string in strings:
        if string.startswith("H4sIAAA"):
            try:
                decoded = decode_b64(revert_string(decompress(decode_b64(string))))
                decoded_json = json.loads(decoded.decode()) # convert to dic
                if decoded_json["SCRT"]:
                    logger.debug(f"DCRatV3 config string found: \n {decoded_json}")
                    conf  = decoded_json
                    continue
            except Exception as e:
                logger.debug(e)

            replace_strings.append(string)

    if conf:
        return conf, replace_strings

    logger.debug("no configuration-string found")
    return

def decrypt_c2(decoded_conf, replace_string):
    c2_conf = json.loads(decoded_conf["SCRT"])
    unzip_decoded = str(decompress(decode_b64(replace_string)))
    # remove byte objects chars
    if unzip_decoded.startswith("b'") and unzip_decoded.endswith("'"):
        unzip_decoded = unzip_decoded[2:-1]
    #Decryption routine
    for i in c2_conf:
        unzip_decoded = unzip_decoded.replace(c2_conf[i],i)
    reverse_unzip_decoded = revert_string(unzip_decoded)
    b64decoded = decode_b64(reverse_unzip_decoded)
    return b64decoded

def extract_C2(decrypted_conf):
    try:
        decrypted_conf_dic = json.loads(decrypted_conf.decode()) # convert to dic
    except Exception as e:
        logger.debug(e)
        return

    c2_temp = {}
    logger.debug(f"trying to extract c2 from {decrypted_conf_dic}")
    for _, value in decrypted_conf_dic.items():
        # only exfil via http has been seen so far (may need to be extended by further protocols)
        if "http" in value.lower():
            # Try to decrypt URL-Path
            try:
                URL_split = value.split('/@')
                URL_path = URL_split[1][::-1]
                URL_path_decoded = base64.b64decode(URL_path).decode('UTF-8')
                URL_decoded = f"{URL_split[0]}/{URL_path_decoded}.php"
                c2_temp .setdefault('c2', []).append(URL_decoded)
            except Exception as e:
                c2_temp .setdefault('c2', []).append(value)

    if c2_temp:
        logger.debug("DCRatV3 C2 found")
        return c2_temp

def get_additional_conf(decoded_conf):

    additional_conf = {}

    for key, value in decoded_conf.items():
        # Skip SCRT and PCRT
        if key in ['SCRT', 'PCRT']:
            continue

        if isinstance(value, str):
            try:
                # Try to parse the string as JSON
                value = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                # If parsing fails, leave the value unchanged
                pass
        # If the value is a dictionary, flatten it further
        if isinstance(value, dict):
            additional_conf.update(value)  # Merge the dictionary into the flat dictionary
        else:
            # Otherwise, just add the key-value pair
            additional_conf[key] = value

    return additional_conf

def extract_config(data):
    with suppress(Exception):

        strings = extract_strings(data=data, minchars=5)
        decoded_conf = find_conf(strings)

        if decoded_conf:
            c2_list = None
            conf , replace_strings = decoded_conf

            #Decrypt Config from SCRT
            for replace_string in replace_strings:
                decrypted_conf =  decrypt_c2(conf, replace_string)
                if decrypted_conf:
                    c2_list = extract_C2(decrypted_conf)
                    if c2_list:
                        break

        additional_conf = get_additional_conf(conf)
        all_conf = {}

        if c2_list:
                all_conf.update(c2_list)
        if additional_conf:
            all_conf.update(additional_conf)

        return all_conf

