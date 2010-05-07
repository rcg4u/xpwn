#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <common.h>
#include <abstractfile.h>

#include <base64.h>
#include <curl/curl.h>
#include <xpwn/img3.h>
#include <xpwn/plist.h>
#include <xpwn/libxpwn.h>
#include <xpwn/nor_files.h>
#include <xpwn/outputstate.h>

#define ECID_BUFSIZE 64

typedef struct TssResponse {
  char* content;
  size_t length;
} TssResponse;

char* createTssRequest(char* ecid, char* input);
TssResponse* sendTssRequest(char* request);
size_t writeCallback(char* data, size_t size, size_t nmemb, TssResponse* response);
void createTssFirmware(TssResponse* response, const char* input, char* output);
void replaceImg3Signature(AbstractFile* file, AbstractFile* signature);
void delchar(char* string, char value);

int main(int argc, char** argv) {
  init_libxpwn(&argc, argv);

  printf("fwstitcher v0.2 - by posixninja\n");
  if (argc != 4) {
    printf("usage: ./fwstitcher <ecid> <input.ipsw> <output.ipsw>\n");
    return 0;
  }

  char* ecid = argv[1];
  char* input = argv[2];
  char* output = argv[3];

  // Create Request
  char* request = createTssRequest(ecid, input);
  if (request != NULL) {

    // Send Request
    TssResponse* response = sendTssRequest(request);
    if (response != NULL) {

      // Create IPSW
      if (strstr(response->content, "MESSAGE=SUCCESS")) {
        createTssFirmware(response, input, output);

      } else {
        fprintf(stderr, "Unable to create personalized IPSW\n");
      }

      free(response->content);
      free(response);
    }

    free(request);
  }

  return 0;
}

char* createTssRequest(char* ecid_string, char* input_ipsw) {
  int chip_id = 0;
  int board_id = 0;
  int security_dom = 0;
  unsigned long long ecid_value = 0;
  OutputState* state = NULL;

  // Extract the build manifest from input ipsw.
  loadZipFile(input_ipsw, &state, "BuildManifest.plist");
  AbstractFile* file = getFileFromOutputState(&state, "BuildManifest.plist");
  if (file == NULL) {
    fprintf(stderr, "Unable to find build manifest\n");
    return NULL;
  }

  Dictionary* root = createDictionaryFromAbstractFile(file);
  if (root == NULL) {
    fprintf(stderr, "Unable to create dictionary from build manifest\n");
    return NULL;
  }

  // Pull device information out of manifest.
  ArrayValue* identities = (ArrayValue*) getValueByKey(root, "BuildIdentities");
  if (identities == NULL) {
    fprintf(stderr, "Unable to find build identities\n");
    return NULL;
  }

  Dictionary* identity = (Dictionary*) identities->values[0];
  if (identity == NULL) {
    fprintf(stderr, "Unable to find restore identity\n");
    return NULL;
  }

  DataValue* build_id = (DataValue*) getValueByKey(identity, "UniqueBuildID");
  if (build_id == NULL) {
    fprintf(stderr, "Unable to find unique build id\n");
    return NULL;
  }

  StringValue* chip_value = (StringValue*) getValueByKey(identity, "ApChipID");
  if (chip_value == NULL) {
    fprintf(stderr, "Unable to find chip id\n");
    return NULL;

  } else {
    sscanf(chip_value->value, "%x", &chip_id);
  }

  StringValue* board_value = (StringValue*) getValueByKey(identity, "ApBoardID");
  if (board_value == NULL) {
    fprintf(stderr, "Unable to find board id\n");
    return NULL;

  } else {
    sscanf(board_value->value, "%x", &board_id);
  }

  StringValue* security_value = (StringValue*) getValueByKey(identity, "ApSecurityDomain");
  if (security_value == NULL) {
    fprintf(stderr, "Unable to find security domain\n");
    return NULL;

  } else {
    sscanf(security_value->value, "%x", &security_dom);
  }

  char* ecid = malloc(ECID_BUFSIZE);
  if (ecid == NULL) {
    fprintf(stderr, "Unable to allocate sufficent memory\n");

  } else {
    memset(ecid, 0, ECID_BUFSIZE);
    sscanf(ecid_string, "%qX", &ecid_value);
    snprintf(ecid, ECID_BUFSIZE, "%qu", ecid_value);
  }

  // Start building the TSS request
  Dictionary* request = createRoot("<dict></dict>");
  addStringToDictionary(request, "@HostIpAddress", "192.168.0.1");
  addStringToDictionary(request, "@HostPlatformInfo", "darwin");
  addStringToDictionary(request, "@VersionInfo", "3.8");
  addStringToDictionary(request, "@Locality", "en_US");
  addBoolToDictionary(request, "ApProductionMode", TRUE);
  addStringToDictionary(request, "ApECID", ecid);
  addIntegerToDictionary(request, "ApChipID", chip_id);
  addIntegerToDictionary(request, "ApBoardID", board_id);
  addIntegerToDictionary(request, "ApSecurityDomain", security_dom);
  addDataToDictionary(request, "UniqueBuildID", build_id->value);

  // Add firmware infomation to request
  Dictionary* manifest = (Dictionary*) getValueByKey(identity, "Manifest");
  if (manifest == NULL) {
    fprintf(stderr, "Unable to find manifest firmware infomation\n");
    return NULL;
  }

  DictValue* firmware = manifest->values;
  DictValue* current = request->values;
  DictValue* previous = NULL;

  while (current != NULL) {
    previous = current;
    current = current->next;
  }

  firmware->prev = previous;
  if (previous == NULL) {
    request->values = firmware;

  } else {
    previous->next = firmware;
  }

  // Remove firmware infomation from the manifest
  current = &manifest->dValue;
  current->prev->next = current->next;
  current->next->prev = current->prev;
  free(current->key);
  free(current);

  // Translate dictionary object into xml
  char* data = getXmlFromRoot(request);

  // Cleanup and return;
  releaseDictionary(request);
  releaseDictionary(root);
  releaseOutput(&state);
  free(ecid);

  return data;
}

// Send the TSS request to fetch the SHSH blobs
TssResponse* sendTssRequest(char* request) {
  curl_global_init(CURL_GLOBAL_ALL);

  TssResponse* response = NULL;
  CURL* handle = curl_easy_init();
  if (handle != NULL) {
    struct curl_slist* header = NULL;
    header = curl_slist_append(header, "Content-type: text/xml");

    response = malloc(sizeof(TssResponse));
    if (response == NULL) {
      fprintf(stderr, "Unable to allocate sufficent memory\n");
      return NULL;
    }

    response->length = 0;
    response->content = malloc(1);

    size_t(*curl_write)(char* data, size_t size, size_t nmemb, TssResponse* response) = &writeCallback;
    curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, curl_write);
    curl_easy_setopt(handle, CURLOPT_WRITEDATA, response);

    curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header);
    curl_easy_setopt(handle, CURLOPT_POSTFIELDS, request);
    curl_easy_setopt(handle, CURLOPT_USERAGENT, "InetURL/1.0");
    curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, strlen(request));
    curl_easy_setopt(handle, CURLOPT_URL, "http://cydia.saurik.com/TSS/controller?action=2");
    //curl_easy_setopt(handle, CURLOPT_URL, "http://gs.apple.com/TSS/controller?action=2");

    curl_easy_perform(handle);
    curl_slist_free_all(header);
    curl_easy_cleanup(handle);
  }

  curl_global_cleanup();
  return response;
}

size_t writeCallback(char* data, size_t size, size_t nmemb, TssResponse* response) {
  size_t total = size * nmemb;
  if (total != 0) {
    response->content = realloc(response->content, response->length + total + 1);
    memcpy(response->content + response->length, data, total);
    response->content[response->length + total] = '\0';
    response->length += total;
  }

  return total;
}

void createTssFirmware(TssResponse* response, const char* input, char* output) {
  char* xml = strstr(response->content, "<?xml");
  if (xml == NULL) {
    fprintf(stderr, "Unable to find xml data in response\n");
    return;
  }

  Dictionary* root = createRoot(xml);
  if (root == NULL) {
    fprintf(stderr, "Unable to generate root from response xml");
    return;
  }

  // Extract entire IPSW
  OutputState* in_state = loadZip(input);
  OutputState* out_state = malloc(sizeof(OutputState));
  while (in_state != NULL) {
    // Search through all entries in our response
    Dictionary* entry = (Dictionary*) root->values;
    while (entry != NULL) {

      // Make sure this entry is a dictionary
      if (entry->dValue.type != DictionaryType) {
        entry = (Dictionary*) entry->dValue.next;
        continue;
      }

      // And that we have the proper values
      StringValue* path = (StringValue*) getValueByKey(entry, "Path");
      StringValue* blob = (StringValue*) getValueByKey(entry, "Blob");
      if (path == NULL || blob == NULL) {
        fprintf(stderr, "Unable to find the proper values in this entry\n");
        entry = (Dictionary*) entry->dValue.next;
        continue;
      }

      // Is this entry match the current one in state
      printf("Replacing SHSH on %s\n", entry->dValue.key);

      char* data = NULL;
      size_t data_size = 0;
      delchar(blob->value, '\t');
      delchar(blob->value, '\n');
      base64_decode_alloc(blob->value, strlen(blob->value), &data, &data_size);

      AbstractFile* signature = createAbstractFileFromMemory((void**) &data, data_size);
      AbstractFile* file = getFileFromOutputState(&in_state, path->value);
      replaceImg3Signature(file, signature);
      char* in_data = malloc(file->getLength(file));
      file->read(file, in_data, file->getLength(file));
      size_t in_len = file->getLength(file);
      addToOutput(&out_state, entry->dValue.key, in_data, in_len);
      signature->close(signature);
      file->close(file);

      char* tmp = createTempFile();
      AbstractFile* store = createAbstractFileFromFile(fopen(tmp, "wb"));
      store->write(store, in_data, file->getLength(file));
      store->close(store);

      //addToOutput2(&out_state, path->value, file->data, file->getLength(file), tmp);
      //removeFileFromOutputState(&in_state, path->value);
      free(data);
      free(tmp);
      entry = (Dictionary*) entry->dValue.next;
    }

    in_state = in_state->next;
  }

  releaseDictionary(root);
  writeOutput(&out_state, output);
}

void replaceImg3Signature(AbstractFile* file, AbstractFile* signature) {
  Img3Info* info = (Img3Info*) file->data;
  size_t signature_size = signature->getLength(signature);
  Img3Element* element = (Img3Element*) readImg3Element(signature);

  int i = 0;
  Img3Element* previous = element;
  for (i = previous->header->size; i < signature_size; i += previous->header->size) {
    previous->next = (Img3Element*) readImg3Element(signature);
    previous = previous->next;
  }

  Img3Element* current = info->data;
  while (current->next != info->shsh) {
    current = current->next;
  }

  signature->seek(signature, 0);
  current->next = element;
  info->dirty = TRUE;
}

void delchar(char* string, char value) {
  while ((string = strchr(string, value))) {
    memmove(string, string + 1, strlen(string));
  }
}
