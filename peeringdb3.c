// Gianluca Mazzini @2016- Version 3.07

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <mariadb/mysql.h>
#include <openssl/sha.h>
#include <zlib.h>

#define PROGRAM_NAME "peeringdb3"
#define PROGRAM_VERSION "3.07"
#define CONFIG_FILE "peeringdb.conf"
#define EXPECTED_TABLES 10
#define API_URL "https://www.peeringdb.com/api/%s?depth=0"
#define USER_AGENT "peeringdb3/3.07 https://peeringdb.mazzini.org/"

#define DB_HOST_LEN 256
#define DB_USER_LEN 128
#define DB_PASS_LEN 256
#define DB_NAME_LEN 128
#define API_KEY_LEN 256
#define TEXT_LEN 256
#define CITY_LEN 129
#define COUNTRY_LEN 3
#define CONTINENT_LEN 33
#define STATUS_LEN 17
#define DATE_LEN 32
#define IP_LEN 46
#define PREFIX_LEN 65
#define SMALL_LEN 65
#define BATCH_ROWS 200
#define PATH_LEN 1024
#define TOPASN_LEN 4096
#define TOPASN20_LEN 8192

#define JSMN_ERROR_NOMEM -1
#define JSMN_ERROR_INVAL -2
#define JSMN_ERROR_PART -3

#define JSMN_UNDEFINED 0
#define JSMN_OBJECT 1
#define JSMN_ARRAY 2
#define JSMN_STRING 3
#define JSMN_PRIMITIVE 4

typedef struct {
  int type;
  int start;
  int end;
  int size;
} JsonToken;

typedef struct {
  unsigned int pos;
  unsigned int toknext;
  int toksuper;
} JsonParser;

typedef struct {
  char host[DB_HOST_LEN];
  char user[DB_USER_LEN];
  char pass[DB_PASS_LEN];
  char name[DB_NAME_LEN];
  char api_key[API_KEY_LEN];
  unsigned int port;
} DbConfig;

typedef struct {
  char *data;
  size_t len;
  size_t cap;
} Buffer;

typedef struct {
  long retry_after;
} HttpInfo;

typedef struct {
  unsigned long long id;
  unsigned long long org_id;
  unsigned long long net_id;
  unsigned long long ix_id;
  unsigned long long ixlan_id;
  unsigned long long fac_id;
  unsigned long long asn;
  unsigned long long speed;
  unsigned long long local_asn;
  unsigned long long mtu;
  int is_rs_peer;
  int operational;
  int dot1q_support;
  int in_dfz;
  char name[TEXT_LEN];
  char name_long[TEXT_LEN];
  char city[CITY_LEN];
  char country[COUNTRY_LEN];
  char continent[CONTINENT_LEN];
  char status[STATUS_LEN];
  char updated[DATE_LEN];
  char info_type[SMALL_LEN];
  char info_scope[SMALL_LEN];
  char protocol[SMALL_LEN];
  char prefix[PREFIX_LEN];
  char ipaddr4[IP_LEN];
  char ipaddr6[IP_LEN];
  char latitude[SMALL_LEN];
  char longitude[SMALL_LEN];
  int raw_start;
  int raw_end;
} PdbRecord;

typedef struct {
  const char *type;
  const char *table;
} ApiDef;

typedef struct {
  unsigned long long id;
  unsigned char hash[SHA256_DIGEST_LENGTH];
} HistoryEntry;

typedef struct {
  unsigned long long *v;
  size_t n;
} IdList;

typedef struct {
  HistoryEntry *v;
  size_t n;
} HistoryList;

typedef struct {
  unsigned long seen;
  unsigned long added;
  unsigned long changed;
  unsigned long removed;
} ImportStats;


typedef struct {
  unsigned long long id;
  unsigned long long asn_count;
  unsigned long long v4_asn_count;
  unsigned long long v6_asn_count;
  unsigned long long dual_asn_count;
  unsigned long long connections;
  unsigned long long total_capacity;
  unsigned long long v4_capacity;
  unsigned long long v6_capacity;
  unsigned long long conn_100g;
  unsigned long long conn_400g;
  unsigned long long conn_800g;
  unsigned long long facility_count;
  unsigned long long lan_count;
  unsigned long long top_capacity;
  int top_count;
  char name[TEXT_LEN];
  char city[CITY_LEN];
  char country[COUNTRY_LEN];
  char continent[CONTINENT_LEN];
  char top_asn[TOPASN_LEN];
  char top20_asn[TOPASN20_LEN];
} IxMetric;

static void json_init(JsonParser *parser) {
  parser->pos=0;
  parser->toknext=0;
  parser->toksuper=-1;
}

static JsonToken *json_alloc(JsonParser *parser,JsonToken *tokens,size_t count) {
  JsonToken *tok;

  if(parser->toknext>=count)return NULL;
  tok=&tokens[parser->toknext++];
  tok->start=-1;
  tok->end=-1;
  tok->size=0;
  tok->type=JSMN_UNDEFINED;
  return tok;
}

static void json_fill(JsonToken *token,int type,int start,int end) {
  token->type=type;
  token->start=start;
  token->end=end;
  token->size=0;
}

static int json_parse_primitive(JsonParser *parser,const char *js,size_t len,
    JsonToken *tokens,size_t count) {
  JsonToken *token;
  int start;
  char c;

  start=(int)parser->pos;
  for(;parser->pos<len;parser->pos++) {
    c=js[parser->pos];
    if(c=='\t' || c=='\r' || c=='\n' || c==' ' || c==',' || c==']' || c=='}')break;
    if((unsigned char)c<32 || (unsigned char)c>=127) {
      parser->pos=(unsigned int)start;
      return JSMN_ERROR_INVAL;
    }
  }
  if(tokens==NULL) {
    parser->pos--;
    return 0;
  }
  token=json_alloc(parser,tokens,count);
  if(!token) {
    parser->pos=(unsigned int)start;
    return JSMN_ERROR_NOMEM;
  }
  json_fill(token,JSMN_PRIMITIVE,start,(int)parser->pos);
  parser->pos--;
  return 0;
}

static int json_parse_string(JsonParser *parser,const char *js,size_t len,
    JsonToken *tokens,size_t count) {
  JsonToken *token;
  int start;
  char c;

  start=(int)parser->pos;
  parser->pos++;
  for(;parser->pos<len;parser->pos++) {
    c=js[parser->pos];
    if(c=='\"') {
      if(tokens==NULL)return 0;
      token=json_alloc(parser,tokens,count);
      if(!token) {
        parser->pos=(unsigned int)start;
        return JSMN_ERROR_NOMEM;
      }
      json_fill(token,JSMN_STRING,start+1,(int)parser->pos);
      return 0;
    }
    if(c=='\\') {
      parser->pos++;
      if(parser->pos>=len)break;
      c=js[parser->pos];
      if(c=='\"' || c=='/' || c=='\\' || c=='b' || c=='f' || c=='r' || c=='n' || c=='t')continue;
      if(c=='u') {
        int i;
        for(i=0;i<4;i++) {
          parser->pos++;
          if(parser->pos>=len)break;
          c=js[parser->pos];
          if(!((c>='0' && c<='9') || (c>='A' && c<='F') || (c>='a' && c<='f'))) {
            parser->pos=(unsigned int)start;
            return JSMN_ERROR_INVAL;
          }
        }
        continue;
      }
      parser->pos=(unsigned int)start;
      return JSMN_ERROR_INVAL;
    }
  }
  parser->pos=(unsigned int)start;
  return JSMN_ERROR_PART;
}

static int json_parse(JsonParser *parser,const char *js,size_t len,
    JsonToken *tokens,unsigned int count) {
  int r;
  int i;
  JsonToken *token;
  JsonToken *open;
  char c;

  for(;parser->pos<len;parser->pos++) {
    c=js[parser->pos];
    switch(c) {
      case '{':
      case '[':
        token=json_alloc(parser,tokens,count);
        if(!token)return JSMN_ERROR_NOMEM;
        if(parser->toksuper!=-1)tokens[parser->toksuper].size++;
        token->type=(c=='{' ? JSMN_OBJECT : JSMN_ARRAY);
        token->start=(int)parser->pos;
        parser->toksuper=(int)parser->toknext-1;
        break;
      case '}':
      case ']':
        if(!tokens)return JSMN_ERROR_INVAL;
        for(i=(int)parser->toknext-1;i>=0;i--) {
          open=&tokens[i];
          if(open->start!=-1 && open->end==-1) {
            if((open->type==JSMN_OBJECT && c=='}') || (open->type==JSMN_ARRAY && c==']')) {
              open->end=(int)parser->pos+1;
              parser->toksuper=-1;
              for(i=i-1;i>=0;i--) {
                if(tokens[i].start!=-1 && tokens[i].end==-1) {
                  parser->toksuper=i;
                  break;
                }
              }
              break;
            }
            return JSMN_ERROR_INVAL;
          }
        }
        if(i==-1 && parser->toksuper!=-1)return JSMN_ERROR_INVAL;
        break;
      case '\"':
        r=json_parse_string(parser,js,len,tokens,count);
        if(r<0)return r;
        if(parser->toksuper!=-1)tokens[parser->toksuper].size++;
        break;
      case '\t':
      case '\r':
      case '\n':
      case ' ':
        break;
      case ':':
        parser->toksuper=(int)parser->toknext-1;
        break;
      case ',':
        if(parser->toksuper!=-1 && tokens[parser->toksuper].type!=JSMN_ARRAY &&
            tokens[parser->toksuper].type!=JSMN_OBJECT) {
          for(i=parser->toksuper-1;i>=0;i--) {
            if(tokens[i].type==JSMN_ARRAY || tokens[i].type==JSMN_OBJECT) {
              if(tokens[i].start!=-1 && tokens[i].end==-1) {
                parser->toksuper=i;
                break;
              }
            }
          }
        }
        break;
      default:
        r=json_parse_primitive(parser,js,len,tokens,count);
        if(r<0)return r;
        if(parser->toksuper!=-1)tokens[parser->toksuper].size++;
        break;
    }
  }
  for(i=(int)parser->toknext-1;i>=0;i--) {
    if(tokens[i].start!=-1 && tokens[i].end==-1)return JSMN_ERROR_PART;
  }
  return (int)parser->toknext;
}

static int token_skip(const JsonToken *tokens,int index) {
  int i;
  int n;

  n=index+1;
  for(i=0;i<tokens[index].size;i++)n=token_skip(tokens,n);
  return n;
}

static int token_eq(const char *json,const JsonToken *token,const char *text) {
  size_t len;

  if(token->type!=JSMN_STRING)return 0;
  len=strlen(text);
  if((size_t)(token->end-token->start)!=len)return 0;
  return !strncmp(json+token->start,text,len);
}

static int object_get(const char *json,const JsonToken *tokens,int object,const char *key) {
  int i;
  int pos;
  int value;

  if(tokens[object].type!=JSMN_OBJECT)return -1;
  pos=object+1;
  for(i=0;i<tokens[object].size;i++) {
    if(tokens[pos].type!=JSMN_STRING)return -1;
    value=pos+1;
    if(token_eq(json,&tokens[pos],key))return value;
    pos=token_skip(tokens,pos);
  }
  return -1;
}

static int hex_value(char c) {
  if(c>='0' && c<='9')return c-'0';
  if(c>='a' && c<='f')return c-'a'+10;
  if(c>='A' && c<='F')return c-'A'+10;
  return -1;
}

static int append_utf8(char *dst,size_t size,size_t *out,unsigned long cp) {
  if(cp<=0x7f) {
    if(*out+1>=size)return -1;
    dst[(*out)++]=(char)cp;
  } else if(cp<=0x7ff) {
    if(*out+2>=size)return -1;
    dst[(*out)++]=(char)(0xc0 | (cp>>6));
    dst[(*out)++]=(char)(0x80 | (cp&0x3f));
  } else if(cp<=0xffff) {
    if(*out+3>=size)return -1;
    dst[(*out)++]=(char)(0xe0 | (cp>>12));
    dst[(*out)++]=(char)(0x80 | ((cp>>6)&0x3f));
    dst[(*out)++]=(char)(0x80 | (cp&0x3f));
  } else if(cp<=0x10ffff) {
    if(*out+4>=size)return -1;
    dst[(*out)++]=(char)(0xf0 | (cp>>18));
    dst[(*out)++]=(char)(0x80 | ((cp>>12)&0x3f));
    dst[(*out)++]=(char)(0x80 | ((cp>>6)&0x3f));
    dst[(*out)++]=(char)(0x80 | (cp&0x3f));
  } else return -1;
  return 0;
}

static int token_string(const char *json,const JsonToken *token,char *dst,size_t size) {
  int i;
  int h1,h2,h3,h4;
  unsigned long cp;
  unsigned long low;
  size_t out;
  char c;

  if(size==0)return -1;
  dst[0]='\0';
  if(token->type==JSMN_PRIMITIVE && token->end-token->start==4 &&
      !strncmp(json+token->start,"null",4))return 0;
  if(token->type!=JSMN_STRING)return -1;

  out=0;
  for(i=token->start;i<token->end;i++) {
    c=json[i];
    if(c!='\\') {
      if(out+1>=size)return -1;
      dst[out++]=c;
      continue;
    }
    i++;
    if(i>=token->end)return -1;
    c=json[i];
    if(c=='\"' || c=='\\' || c=='/') {
      if(out+1>=size)return -1;
      dst[out++]=c;
    } else if(c=='b' || c=='f' || c=='n' || c=='r' || c=='t') {
      if(out+1>=size)return -1;
      if(c=='b')dst[out++]='\b';
      else if(c=='f')dst[out++]='\f';
      else if(c=='n')dst[out++]='\n';
      else if(c=='r')dst[out++]='\r';
      else dst[out++]='\t';
    } else if(c=='u') {
      if(i+4>=token->end)return -1;
      h1=hex_value(json[i+1]);
      h2=hex_value(json[i+2]);
      h3=hex_value(json[i+3]);
      h4=hex_value(json[i+4]);
      if(h1<0 || h2<0 || h3<0 || h4<0)return -1;
      cp=(unsigned long)((h1<<12)|(h2<<8)|(h3<<4)|h4);
      i+=4;
      if(cp>=0xd800 && cp<=0xdbff && i+6<token->end && json[i+1]=='\\' && json[i+2]=='u') {
        h1=hex_value(json[i+3]);
        h2=hex_value(json[i+4]);
        h3=hex_value(json[i+5]);
        h4=hex_value(json[i+6]);
        if(h1>=0 && h2>=0 && h3>=0 && h4>=0) {
          low=(unsigned long)((h1<<12)|(h2<<8)|(h3<<4)|h4);
          if(low>=0xdc00 && low<=0xdfff) {
            cp=0x10000+((cp-0xd800)<<10)+(low-0xdc00);
            i+=6;
          }
        }
      }
      if(append_utf8(dst,size,&out,cp)!=0)return -1;
    } else return -1;
  }
  dst[out]='\0';
  return 0;
}

static int token_u64(const char *json,const JsonToken *token,unsigned long long *value) {
  char buf[64];
  char *end;
  size_t len;

  *value=0;
  if(token->type==JSMN_PRIMITIVE && token->end-token->start==4 &&
      !strncmp(json+token->start,"null",4))return 0;
  if(token->type!=JSMN_PRIMITIVE)return -1;
  len=(size_t)(token->end-token->start);
  if(len==0 || len>=sizeof(buf))return -1;
  memcpy(buf,json+token->start,len);
  buf[len]='\0';
  end=NULL;
  *value=strtoull(buf,&end,10);
  if(!end || *end)return -1;
  return 0;
}

static int token_datetime(const char *json,const JsonToken *token,char *dst,size_t size) {
  char tmp[64];
  size_t len;

  if(token_string(json,token,tmp,sizeof(tmp))!=0)return -1;
  if(!tmp[0]) {
    dst[0]='\0';
    return 0;
  }
  len=strlen(tmp);
  if(len<19 || size<20)return -1;
  memcpy(dst,tmp,19);
  dst[10]=' ';
  dst[19]='\0';
  return 0;
}

static char *trim(char *s) {
  char *end;

  while(*s && isspace((unsigned char)*s))s++;
  if(!*s)return s;
  end=s+strlen(s)-1;
  while(end>s && isspace((unsigned char)*end))end--;
  end[1]='\0';
  return s;
}

static int copy_value(char *dst,size_t size,const char *value,const char *key) {
  size_t len;

  len=strlen(value);
  if(len>=size) {
    fprintf(stderr,"%s: value too long for %s\n",PROGRAM_NAME,key);
    return -1;
  }
  memcpy(dst,value,len+1);
  return 0;
}

static int load_config(DbConfig *cfg) {
  FILE *fp;
  char line[1024];
  char *key,*value,*eq,*end;
  unsigned long port;
  int lineno;

  memset(cfg,0,sizeof(*cfg));
  cfg->port=3306;
  fp=fopen(CONFIG_FILE,"r");
  if(!fp) {
    fprintf(stderr,"%s: cannot open %s\n",PROGRAM_NAME,CONFIG_FILE);
    return -1;
  }
  lineno=0;
  while(fgets(line,sizeof(line),fp)) {
    lineno++;
    key=trim(line);
    if(!*key || *key=='#')continue;
    eq=strchr(key,'=');
    if(!eq) {
      fprintf(stderr,"%s:%d: expected key=value\n",CONFIG_FILE,lineno);
      fclose(fp);
      return -1;
    }
    *eq='\0';
    value=trim(eq+1);
    key=trim(key);
    if(!strcmp(key,"db_host")) {
      if(copy_value(cfg->host,sizeof(cfg->host),value,key)!=0)goto fail;
    } else if(!strcmp(key,"db_user")) {
      if(copy_value(cfg->user,sizeof(cfg->user),value,key)!=0)goto fail;
    } else if(!strcmp(key,"db_pass")) {
      if(copy_value(cfg->pass,sizeof(cfg->pass),value,key)!=0)goto fail;
    } else if(!strcmp(key,"db_name")) {
      if(copy_value(cfg->name,sizeof(cfg->name),value,key)!=0)goto fail;
    } else if(!strcmp(key,"api_key")) {
      if(copy_value(cfg->api_key,sizeof(cfg->api_key),value,key)!=0)goto fail;
    } else if(!strcmp(key,"db_port")) {
      end=NULL;
      port=strtoul(value,&end,10);
      if(!*value || !end || *end || port==0 || port>65535) {
        fprintf(stderr,"%s:%d: invalid db_port\n",CONFIG_FILE,lineno);
        goto fail;
      }
      cfg->port=(unsigned int)port;
    } else {
      fprintf(stderr,"%s:%d: unknown key '%s'\n",CONFIG_FILE,lineno,key);
      goto fail;
    }
  }
  if(ferror(fp))goto fail;
  fclose(fp);
  if(!cfg->host[0] || !cfg->user[0] || !cfg->pass[0] || !cfg->name[0]) {
    fprintf(stderr,"%s: incomplete database configuration\n",PROGRAM_NAME);
    return -1;
  }
  return 0;
fail:
  fclose(fp);
  return -1;
}

static MYSQL *db_connect(const DbConfig *cfg) {
  MYSQL *db;

  db=mysql_init(NULL);
  if(!db)return NULL;
  if(!mysql_real_connect(db,cfg->host,cfg->user,cfg->pass,cfg->name,cfg->port,NULL,0)) {
    fprintf(stderr,"%s: database connection failed: %s\n",PROGRAM_NAME,mysql_error(db));
    mysql_close(db);
    return NULL;
  }
  mysql_set_character_set(db,"utf8mb4");
  return db;
}

static size_t curl_write(void *ptr,size_t size,size_t nmemb,void *userdata) {
  Buffer *buf;
  size_t bytes;
  size_t need;
  size_t cap;
  char *newdata;

  buf=(Buffer *)userdata;
  bytes=size*nmemb;
  if(bytes==0)return 0;
  need=buf->len+bytes+1;
  if(need>buf->cap) {
    cap=buf->cap ? buf->cap : 65536;
    while(cap<need)cap*=2;
    newdata=(char *)realloc(buf->data,cap);
    if(!newdata)return 0;
    buf->data=newdata;
    buf->cap=cap;
  }
  memcpy(buf->data+buf->len,ptr,bytes);
  buf->len+=bytes;
  buf->data[buf->len]='\0';
  return bytes;
}

static size_t curl_header(void *ptr,size_t size,size_t nmemb,void *userdata) {
  HttpInfo *info;
  char *line;
  size_t len;
  char *p;

  info=(HttpInfo *)userdata;
  line=(char *)ptr;
  len=size*nmemb;
  if(len>12 && !strncasecmp(line,"Retry-After:",12)) {
    p=line+12;
    while((size_t)(p-line)<len && isspace((unsigned char)*p))p++;
    info->retry_after=strtol(p,NULL,10);
  }
  return len;
}

static int http_get(const char *url,const char *api_key,Buffer *buf) {
  CURL *curl;
  CURLcode rc;
  struct curl_slist *headers;
  HttpInfo info;
  char auth[API_KEY_LEN+32];
  long status;
  long delay;
  int attempt;

  memset(buf,0,sizeof(*buf));
  for(attempt=0;attempt<4;attempt++) {
    buf->len=0;
    if(buf->data)buf->data[0]='\0';
    memset(&info,0,sizeof(info));
    headers=NULL;
    curl=curl_easy_init();
    if(!curl)return -1;
    if(api_key && api_key[0]) {
      if(snprintf(auth,sizeof(auth),"Authorization: Api-Key %s",api_key)<0) {
        curl_easy_cleanup(curl);
        return -1;
      }
      headers=curl_slist_append(headers,auth);
      if(!headers) {
        curl_easy_cleanup(curl);
        return -1;
      }
      curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers);
    }
    curl_easy_setopt(curl,CURLOPT_URL,url);
    curl_easy_setopt(curl,CURLOPT_USERAGENT,USER_AGENT);
    curl_easy_setopt(curl,CURLOPT_ACCEPT_ENCODING,"");
    curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,20L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,180L);
    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_write);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA,buf);
    curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,curl_header);
    curl_easy_setopt(curl,CURLOPT_HEADERDATA,&info);
    rc=curl_easy_perform(curl);
    status=0;
    curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    if(rc==CURLE_OK && status==200)return 0;
    if(rc==CURLE_OK && status==429) {
      delay=info.retry_after>0 ? info.retry_after : 60;
      if(delay>300 || attempt==3) {
        fprintf(stderr,"%s: HTTP 429 retry-after=%ld%s\n",PROGRAM_NAME,delay,
          api_key && api_key[0] ? "" : " (consider api_key in peeringdb.conf)");
        break;
      }
      fprintf(stderr,"%s: HTTP 429, retry in %ld seconds\n",PROGRAM_NAME,delay);
      sleep((unsigned int)delay);
      continue;
    }
    if(rc==CURLE_OK && (status==502 || status==503 || status==504) && attempt<3) {
      sleep(10);
      continue;
    }
    fprintf(stderr,"%s: HTTP failed: %s status=%ld\n",PROGRAM_NAME,
      rc==CURLE_OK ? "HTTP error" : curl_easy_strerror(rc),status);
    break;
  }
  free(buf->data);
  memset(buf,0,sizeof(*buf));
  return -1;
}

static int parse_json(const char *json,size_t len,JsonToken **out_tokens,int *out_count) {
  JsonParser parser;
  JsonToken *tokens;
  size_t cap;
  int count;

  cap=len/8+1024;
  if(cap<4096)cap=4096;
  for(;;) {
    tokens=(JsonToken *)malloc(cap*sizeof(JsonToken));
    if(!tokens)return -1;
    json_init(&parser);
    count=json_parse(&parser,json,len,tokens,(unsigned int)cap);
    if(count!=JSMN_ERROR_NOMEM)break;
    free(tokens);
    cap*=2;
  }
  if(count<0) {
    fprintf(stderr,"%s: invalid JSON (%d)\n",PROGRAM_NAME,count);
    free(tokens);
    return -1;
  }
  *out_tokens=tokens;
  *out_count=count;
  return 0;
}

static int token_bool(const char *json,const JsonToken *token,int *value) {
  if(token->type!=JSMN_PRIMITIVE)return -1;
  if(token->end-token->start==4 && !strncmp(json+token->start,"true",4)) {
    *value=1;
    return 0;
  }
  if(token->end-token->start==5 && !strncmp(json+token->start,"false",5)) {
    *value=0;
    return 0;
  }
  if(token->end-token->start==4 && !strncmp(json+token->start,"null",4)) {
    *value=-1;
    return 0;
  }
  return -1;
}

static int token_scalar(const char *json,const JsonToken *token,char *dst,size_t size) {
  size_t len;

  if(token->type==JSMN_STRING)return token_string(json,token,dst,size);
  if(token->type!=JSMN_PRIMITIVE)return -1;
  len=(size_t)(token->end-token->start);
  if(len==4 && !strncmp(json+token->start,"null",4)) {
    dst[0]='\0';
    return 0;
  }
  if(len>=size)return -1;
  memcpy(dst,json+token->start,len);
  dst[len]='\0';
  return 0;
}

static int field_string(const char *json,const JsonToken *tokens,int object,
    const char *key,char *dst,size_t size) {
  int t;

  t=object_get(json,tokens,object,key);
  if(t<0) {
    dst[0]='\0';
    return 0;
  }
  return token_string(json,&tokens[t],dst,size);
}

static int field_scalar(const char *json,const JsonToken *tokens,int object,
    const char *key,char *dst,size_t size) {
  int t;

  t=object_get(json,tokens,object,key);
  if(t<0) {
    dst[0]='\0';
    return 0;
  }
  return token_scalar(json,&tokens[t],dst,size);
}

static int field_u64(const char *json,const JsonToken *tokens,int object,
    const char *key,unsigned long long *value) {
  int t;

  *value=0;
  t=object_get(json,tokens,object,key);
  if(t<0)return 0;
  return token_u64(json,&tokens[t],value);
}

static int field_bool(const char *json,const JsonToken *tokens,int object,
    const char *key,int *value) {
  int t;

  *value=-1;
  t=object_get(json,tokens,object,key);
  if(t<0)return 0;
  return token_bool(json,&tokens[t],value);
}

static int parse_record(const char *json,const JsonToken *tokens,int object,PdbRecord *r) {
  int t;

  memset(r,0,sizeof(*r));
  r->is_rs_peer=-1;
  r->operational=1;
  r->dot1q_support=-1;
  r->in_dfz=-1;
  r->raw_start=tokens[object].start;
  r->raw_end=tokens[object].end;

  t=object_get(json,tokens,object,"id");
  if(t<0 || token_u64(json,&tokens[t],&r->id)!=0 || r->id==0)return -1;
  if(field_u64(json,tokens,object,"org_id",&r->org_id)!=0)return -1;
  if(field_u64(json,tokens,object,"net_id",&r->net_id)!=0)return -1;
  if(field_u64(json,tokens,object,"ix_id",&r->ix_id)!=0)return -1;
  if(field_u64(json,tokens,object,"ixlan_id",&r->ixlan_id)!=0)return -1;
  if(field_u64(json,tokens,object,"fac_id",&r->fac_id)!=0)return -1;
  if(field_u64(json,tokens,object,"asn",&r->asn)!=0)return -1;
  if(field_u64(json,tokens,object,"speed",&r->speed)!=0)return -1;
  if(field_u64(json,tokens,object,"local_asn",&r->local_asn)!=0)return -1;
  if(field_u64(json,tokens,object,"mtu",&r->mtu)!=0)return -1;
  if(field_bool(json,tokens,object,"is_rs_peer",&r->is_rs_peer)!=0)return -1;
  if(field_bool(json,tokens,object,"operational",&r->operational)!=0)return -1;
  if(field_bool(json,tokens,object,"dot1q_support",&r->dot1q_support)!=0)return -1;
  if(field_bool(json,tokens,object,"in_dfz",&r->in_dfz)!=0)return -1;
  if(field_string(json,tokens,object,"name",r->name,sizeof(r->name))!=0)return -1;
  if(field_string(json,tokens,object,"name_long",r->name_long,sizeof(r->name_long))!=0)return -1;
  if(field_string(json,tokens,object,"city",r->city,sizeof(r->city))!=0)return -1;
  if(field_string(json,tokens,object,"country",r->country,sizeof(r->country))!=0)return -1;
  if(field_string(json,tokens,object,"region_continent",r->continent,sizeof(r->continent))!=0)return -1;
  if(field_string(json,tokens,object,"status",r->status,sizeof(r->status))!=0)return -1;
  if(field_string(json,tokens,object,"info_type",r->info_type,sizeof(r->info_type))!=0)return -1;
  if(field_string(json,tokens,object,"info_scope",r->info_scope,sizeof(r->info_scope))!=0)return -1;
  if(field_string(json,tokens,object,"protocol",r->protocol,sizeof(r->protocol))!=0)return -1;
  if(field_string(json,tokens,object,"prefix",r->prefix,sizeof(r->prefix))!=0)return -1;
  if(field_string(json,tokens,object,"ipaddr4",r->ipaddr4,sizeof(r->ipaddr4))!=0)return -1;
  if(field_string(json,tokens,object,"ipaddr6",r->ipaddr6,sizeof(r->ipaddr6))!=0)return -1;
  if(field_scalar(json,tokens,object,"latitude",r->latitude,sizeof(r->latitude))!=0)return -1;
  if(field_scalar(json,tokens,object,"longitude",r->longitude,sizeof(r->longitude))!=0)return -1;
  t=object_get(json,tokens,object,"updated");
  if(t>=0 && token_datetime(json,&tokens[t],r->updated,sizeof(r->updated))!=0)return -1;
  return 0;
}

static int cmp_history(const void *a,const void *b) {
  const HistoryEntry *x;
  const HistoryEntry *y;

  x=(const HistoryEntry *)a;
  y=(const HistoryEntry *)b;
  if(x->id<y->id)return -1;
  if(x->id>y->id)return 1;
  return 0;
}

static int cmp_id(const void *a,const void *b) {
  const unsigned long long *x;
  const unsigned long long *y;

  x=(const unsigned long long *)a;
  y=(const unsigned long long *)b;
  if(*x<*y)return -1;
  if(*x>*y)return 1;
  return 0;
}

static const HistoryEntry *history_find(const HistoryList *list,unsigned long long id) {
  HistoryEntry key;

  key.id=id;
  memset(key.hash,0,sizeof(key.hash));
  return (const HistoryEntry *)bsearch(&key,list->v,list->n,sizeof(HistoryEntry),cmp_history);
}

static int id_find(const IdList *list,unsigned long long id) {
  return bsearch(&id,list->v,list->n,sizeof(unsigned long long),cmp_id)!=NULL;
}

static int id_push(IdList *list,unsigned long long id) {
  unsigned long long *v;

  v=(unsigned long long *)realloc(list->v,(list->n+1)*sizeof(unsigned long long));
  if(!v)return -1;
  list->v=v;
  list->v[list->n++]=id;
  return 0;
}

static int buffer_reserve(Buffer *buf,size_t extra) {
  size_t need;
  size_t cap;
  char *data;

  need=buf->len+extra+1;
  if(need<=buf->cap)return 0;
  cap=buf->cap ? buf->cap : 4096;
  while(cap<need)cap*=2;
  data=(char *)realloc(buf->data,cap);
  if(!data)return -1;
  buf->data=data;
  buf->cap=cap;
  return 0;
}

static int buffer_append(Buffer *buf,const char *s,size_t len) {
  if(buffer_reserve(buf,len)!=0)return -1;
  memcpy(buf->data+buf->len,s,len);
  buf->len+=len;
  buf->data[buf->len]='\0';
  return 0;
}

static int buffer_puts(Buffer *buf,const char *s) {
  return buffer_append(buf,s,strlen(s));
}

static int buffer_printf(Buffer *buf,const char *fmt,...) {
  va_list ap;
  va_list cp;
  int n;

  va_start(ap,fmt);
  va_copy(cp,ap);
  n=vsnprintf(NULL,0,fmt,cp);
  va_end(cp);
  if(n<0) {
    va_end(ap);
    return -1;
  }
  if(buffer_reserve(buf,(size_t)n)!=0) {
    va_end(ap);
    return -1;
  }
  vsnprintf(buf->data+buf->len,buf->cap-buf->len,fmt,ap);
  va_end(ap);
  buf->len+=(size_t)n;
  return 0;
}

static void buffer_reset(Buffer *buf) {
  buf->len=0;
  if(buf->data)buf->data[0]='\0';
}

static int sql_string(MYSQL *db,Buffer *buf,const char *s) {
  size_t len;
  char *escaped;
  unsigned long out;
  int rc;

  len=strlen(s);
  escaped=(char *)malloc(len*2+1);
  if(!escaped)return -1;
  out=mysql_real_escape_string(db,escaped,s,(unsigned long)len);
  rc=buffer_puts(buf,"'");
  if(rc==0)rc=buffer_append(buf,escaped,(size_t)out);
  if(rc==0)rc=buffer_puts(buf,"'");
  free(escaped);
  return rc;
}

static int sql_nullable_string(MYSQL *db,Buffer *buf,const char *s) {
  if(!s[0])return buffer_puts(buf,"NULL");
  return sql_string(db,buf,s);
}

static int sql_nullable_u64(Buffer *buf,unsigned long long v) {
  if(v==0)return buffer_puts(buf,"NULL");
  return buffer_printf(buf,"%llu",v);
}

static int sql_nullable_bool(Buffer *buf,int v) {
  if(v<0)return buffer_puts(buf,"NULL");
  return buffer_printf(buf,"%d",v ? 1 : 0);
}

static int sql_ip(MYSQL *db,Buffer *buf,const char *s) {
  if(!s[0])return buffer_puts(buf,"NULL");
  if(buffer_puts(buf,"INET6_ATON(")!=0)return -1;
  if(sql_string(db,buf,s)!=0)return -1;
  return buffer_puts(buf,")");
}

static int sql_decimal(Buffer *buf,const char *s) {
  const char *p;

  if(!s[0])return buffer_puts(buf,"NULL");
  p=s;
  if(*p=='-' || *p=='+')p++;
  if(!*p)return -1;
  for(;*p;p++)if(!isdigit((unsigned char)*p) && *p!='.')return -1;
  return buffer_puts(buf,s);
}

static int load_history(MYSQL *db,const ApiDef *def,HistoryList *list) {
  Buffer q;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long *lengths;
  size_t cap;

  memset(&q,0,sizeof(q));
  memset(list,0,sizeof(*list));
  if(buffer_puts(&q,"SELECT pdb_id,content_hash FROM object_history WHERE object_type=")!=0 ||
      sql_string(db,&q,def->type)!=0 || buffer_puts(&q," AND valid_to IS NULL")!=0)goto fail;
  if(mysql_query(db,q.data)!=0)goto fail;
  res=mysql_store_result(db);
  if(!res)goto fail;
  cap=(size_t)mysql_num_rows(res);
  if(cap) {
    list->v=(HistoryEntry *)calloc(cap,sizeof(HistoryEntry));
    if(!list->v) {
      mysql_free_result(res);
      goto fail;
    }
  }
  while((row=mysql_fetch_row(res))!=NULL) {
    lengths=mysql_fetch_lengths(res);
    if(!row[0] || !row[1] || !lengths || lengths[1]!=SHA256_DIGEST_LENGTH) {
      mysql_free_result(res);
      goto fail_list;
    }
    list->v[list->n].id=strtoull(row[0],NULL,10);
    memcpy(list->v[list->n].hash,row[1],SHA256_DIGEST_LENGTH);
    list->n++;
  }
  mysql_free_result(res);
  qsort(list->v,list->n,sizeof(HistoryEntry),cmp_history);
  free(q.data);
  return 0;
fail_list:
  free(list->v);
  memset(list,0,sizeof(*list));
fail:
  free(q.data);
  return -1;
}

static int load_current_ids(MYSQL *db,const ApiDef *def,IdList *list) {
  Buffer q;
  MYSQL_RES *res;
  MYSQL_ROW row;
  size_t cap;

  memset(&q,0,sizeof(q));
  memset(list,0,sizeof(*list));
  if(buffer_printf(&q,"SELECT id FROM %s",def->table)!=0)goto fail;
  if(mysql_query(db,q.data)!=0)goto fail;
  res=mysql_store_result(db);
  if(!res)goto fail;
  cap=(size_t)mysql_num_rows(res);
  if(cap) {
    list->v=(unsigned long long *)malloc(cap*sizeof(unsigned long long));
    if(!list->v) {
      mysql_free_result(res);
      goto fail;
    }
  }
  while((row=mysql_fetch_row(res))!=NULL) {
    if(row[0])list->v[list->n++]=strtoull(row[0],NULL,10);
  }
  mysql_free_result(res);
  qsort(list->v,list->n,sizeof(unsigned long long),cmp_id);
  free(q.data);
  return 0;
fail:
  free(q.data);
  free(list->v);
  memset(list,0,sizeof(*list));
  return -1;
}

static int db_timestamp(MYSQL *db,char *stamp,size_t size) {
  MYSQL_RES *res;
  MYSQL_ROW row;

  if(mysql_query(db,"SELECT DATE_FORMAT(NOW(6),'%Y-%m-%d %H:%i:%s.%f')")!=0)return -1;
  res=mysql_store_result(db);
  if(!res)return -1;
  row=mysql_fetch_row(res);
  if(!row || !row[0] || strlen(row[0])>=size) {
    mysql_free_result(res);
    return -1;
  }
  strcpy(stamp,row[0]);
  mysql_free_result(res);
  return 0;
}

static const char *current_head(const ApiDef *def) {
  if(!strcmp(def->type,"org"))return "INSERT INTO organization_current(id,name,country,city,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"fac"))return "INSERT INTO facility_current(id,org_id,name,city,country,latitude,longitude,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"ix"))return "INSERT INTO ix_current(id,org_id,name,name_long,city,country,continent,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"ixfac"))return "INSERT INTO ixfac_current(id,ix_id,fac_id,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"ixlan"))return "INSERT INTO ixlan_current(id,ix_id,name,mtu,dot1q_support,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"ixpfx"))return "INSERT INTO ixpfx_current(id,ixlan_id,protocol,prefix,in_dfz,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"net"))return "INSERT INTO network_current(id,org_id,asn,name,info_type,info_scope,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"netfac"))return "INSERT INTO netfac_current(id,net_id,fac_id,local_asn,status,source_updated_at) VALUES ";
  if(!strcmp(def->type,"netixlan"))return "INSERT INTO netixlan_current(id,net_id,ix_id,ixlan_id,asn,speed_mbps,ipaddr4,ipaddr6,is_rs_peer,operational,status,source_updated_at) VALUES ";
  return NULL;
}

static const char *current_tail(const ApiDef *def) {
  if(!strcmp(def->type,"org"))return " ON DUPLICATE KEY UPDATE name=VALUES(name),country=VALUES(country),city=VALUES(city),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"fac"))return " ON DUPLICATE KEY UPDATE org_id=VALUES(org_id),name=VALUES(name),city=VALUES(city),country=VALUES(country),latitude=VALUES(latitude),longitude=VALUES(longitude),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"ix"))return " ON DUPLICATE KEY UPDATE org_id=VALUES(org_id),name=VALUES(name),name_long=VALUES(name_long),city=VALUES(city),country=VALUES(country),continent=VALUES(continent),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"ixfac"))return " ON DUPLICATE KEY UPDATE ix_id=VALUES(ix_id),fac_id=VALUES(fac_id),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"ixlan"))return " ON DUPLICATE KEY UPDATE ix_id=VALUES(ix_id),name=VALUES(name),mtu=VALUES(mtu),dot1q_support=VALUES(dot1q_support),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"ixpfx"))return " ON DUPLICATE KEY UPDATE ixlan_id=VALUES(ixlan_id),protocol=VALUES(protocol),prefix=VALUES(prefix),in_dfz=VALUES(in_dfz),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"net"))return " ON DUPLICATE KEY UPDATE org_id=VALUES(org_id),asn=VALUES(asn),name=VALUES(name),info_type=VALUES(info_type),info_scope=VALUES(info_scope),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"netfac"))return " ON DUPLICATE KEY UPDATE net_id=VALUES(net_id),fac_id=VALUES(fac_id),local_asn=VALUES(local_asn),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  if(!strcmp(def->type,"netixlan"))return " ON DUPLICATE KEY UPDATE net_id=VALUES(net_id),ix_id=VALUES(ix_id),ixlan_id=VALUES(ixlan_id),asn=VALUES(asn),speed_mbps=VALUES(speed_mbps),ipaddr4=VALUES(ipaddr4),ipaddr6=VALUES(ipaddr6),is_rs_peer=VALUES(is_rs_peer),operational=VALUES(operational),status=VALUES(status),source_updated_at=VALUES(source_updated_at)";
  return NULL;
}

static int append_current_tuple(MYSQL *db,Buffer *q,const ApiDef *def,const PdbRecord *r) {
  if(buffer_printf(q,"(%llu,",r->id)!=0)return -1;
  if(!strcmp(def->type,"org")) {
    if(sql_string(db,q,r->name)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->country)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->city)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"fac")) {
    if(sql_nullable_u64(q,r->org_id)!=0 || buffer_puts(q,",")!=0 || sql_string(db,q,r->name)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->city)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->country)!=0 || buffer_puts(q,",")!=0 ||
        sql_decimal(q,r->latitude)!=0 || buffer_puts(q,",")!=0 || sql_decimal(q,r->longitude)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"ix")) {
    if(sql_nullable_u64(q,r->org_id)!=0 || buffer_puts(q,",")!=0 || sql_string(db,q,r->name)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->name_long)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->city)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->country)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->continent)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"ixfac")) {
    if(buffer_printf(q,"%llu,%llu,",r->ix_id,r->fac_id)!=0 || sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"ixlan")) {
    if(buffer_printf(q,"%llu,",r->ix_id)!=0 || sql_nullable_string(db,q,r->name)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_u64(q,r->mtu)!=0 || buffer_puts(q,",")!=0 || sql_nullable_bool(q,r->dot1q_support)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"ixpfx")) {
    if(buffer_printf(q,"%llu,",r->ixlan_id)!=0 || sql_nullable_string(db,q,r->protocol)!=0 || buffer_puts(q,",")!=0 ||
        sql_string(db,q,r->prefix)!=0 || buffer_puts(q,",")!=0 || sql_nullable_bool(q,r->in_dfz)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"net")) {
    if(sql_nullable_u64(q,r->org_id)!=0 || buffer_printf(q,",%llu,",r->asn)!=0 || sql_string(db,q,r->name)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->info_type)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->info_scope)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"netfac")) {
    if(buffer_printf(q,"%llu,%llu,",r->net_id,r->fac_id)!=0 || sql_nullable_u64(q,r->local_asn)!=0 || buffer_puts(q,",")!=0 ||
        sql_nullable_string(db,q,r->status)!=0 || buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else if(!strcmp(def->type,"netixlan")) {
    if(buffer_printf(q,"%llu,%llu,",r->net_id,r->ix_id)!=0 || sql_nullable_u64(q,r->ixlan_id)!=0 || buffer_printf(q,",%llu,%llu,",r->asn,r->speed)!=0 ||
        sql_ip(db,q,r->ipaddr4)!=0 || buffer_puts(q,",")!=0 || sql_ip(db,q,r->ipaddr6)!=0 || buffer_puts(q,",")!=0 ||
        buffer_printf(q,"%d,%d,",r->is_rs_peer>0 ? 1 : 0,r->operational==0 ? 0 : 1)!=0 || sql_nullable_string(db,q,r->status)!=0 ||
        buffer_puts(q,",")!=0 || sql_nullable_string(db,q,r->updated)!=0)return -1;
  } else return -1;
  return buffer_puts(q,")");
}

static int flush_current(MYSQL *db,Buffer *q,const ApiDef *def,int *rows) {
  const char *tail;

  if(*rows==0)return 0;
  tail=current_tail(def);
  if(!tail || buffer_puts(q,tail)!=0)return -1;
  if(mysql_query(db,q->data)!=0) {
    fprintf(stderr,"%s: %s current write failed: %s\n",PROGRAM_NAME,def->type,mysql_error(db));
    return -1;
  }
  buffer_reset(q);
  *rows=0;
  return 0;
}

static int add_current(MYSQL *db,Buffer *q,const ApiDef *def,const PdbRecord *r,int *rows) {
  const char *head;

  if(*rows==0) {
    head=current_head(def);
    if(!head || buffer_puts(q,head)!=0)return -1;
  } else if(buffer_puts(q,",")!=0)return -1;
  if(append_current_tuple(db,q,def,r)!=0)return -1;
  (*rows)++;
  if(*rows>=BATCH_ROWS)return flush_current(db,q,def,rows);
  return 0;
}

static int append_hex(Buffer *q,const unsigned char *data,size_t len) {
  static const char hex[]="0123456789abcdef";
  size_t i;
  char pair[2];

  if(buffer_reserve(q,len*2)!=0)return -1;
  for(i=0;i<len;i++) {
    pair[0]=hex[data[i]>>4];
    pair[1]=hex[data[i]&15];
    if(buffer_append(q,pair,2)!=0)return -1;
  }
  return 0;
}

static int add_history(MYSQL *db,Buffer *q,const ApiDef *def,const PdbRecord *r,
    const unsigned char hash[SHA256_DIGEST_LENGTH],const char *raw,size_t raw_len,
    const char *stamp,int *rows) {
  unsigned char *compressed;
  uLongf compressed_len;
  int rc;

  if(*rows==0) {
    if(buffer_puts(q,"INSERT INTO object_history(object_type,pdb_id,valid_from,valid_to,source_updated_at,content_hash,payload_codec,payload_size,payload) VALUES ")!=0)return -1;
  } else if(buffer_puts(q,",")!=0)return -1;

  compressed_len=compressBound((uLong)raw_len);
  compressed=(unsigned char *)malloc((size_t)compressed_len);
  if(!compressed)return -1;
  rc=compress2(compressed,&compressed_len,(const Bytef *)raw,(uLong)raw_len,Z_BEST_SPEED);
  if(rc!=Z_OK) {
    free(compressed);
    return -1;
  }

  if(buffer_puts(q,"(")!=0 || sql_string(db,q,def->type)!=0 || buffer_printf(q,",%llu,",r->id)!=0 ||
      sql_string(db,q,stamp)!=0 || buffer_puts(q,",NULL,")!=0 || sql_nullable_string(db,q,r->updated)!=0 ||
      buffer_puts(q,",UNHEX('")!=0 || append_hex(q,hash,SHA256_DIGEST_LENGTH)!=0 ||
      buffer_printf(q,"'),1,%lu,UNHEX('",(unsigned long)raw_len)!=0 ||
      append_hex(q,compressed,(size_t)compressed_len)!=0 || buffer_puts(q,"'))")!=0) {
    free(compressed);
    return -1;
  }
  free(compressed);
  (*rows)++;
  if(*rows>=BATCH_ROWS) {
    if(mysql_query(db,q->data)!=0) {
      fprintf(stderr,"%s: %s history write failed: %s\n",PROGRAM_NAME,def->type,mysql_error(db));
      return -1;
    }
    buffer_reset(q);
    *rows=0;
  }
  return 0;
}

static int flush_history(MYSQL *db,Buffer *q,const ApiDef *def,int *rows) {
  if(*rows==0)return 0;
  if(mysql_query(db,q->data)!=0) {
    fprintf(stderr,"%s: %s history write failed: %s\n",PROGRAM_NAME,def->type,mysql_error(db));
    return -1;
  }
  buffer_reset(q);
  *rows=0;
  return 0;
}

static int close_history_ids(MYSQL *db,const ApiDef *def,const IdList *ids,const char *stamp) {
  Buffer q;
  size_t i;
  size_t n;

  memset(&q,0,sizeof(q));
  i=0;
  while(i<ids->n) {
    buffer_reset(&q);
    if(buffer_puts(&q,"UPDATE object_history SET valid_to=")!=0 || sql_string(db,&q,stamp)!=0 ||
        buffer_puts(&q," WHERE valid_to IS NULL AND object_type=")!=0 || sql_string(db,&q,def->type)!=0 ||
        buffer_puts(&q," AND pdb_id IN (")!=0)goto fail;
    n=0;
    while(i<ids->n && n<BATCH_ROWS*2) {
      if(n && buffer_puts(&q,",")!=0)goto fail;
      if(buffer_printf(&q,"%llu",ids->v[i])!=0)goto fail;
      i++;
      n++;
    }
    if(buffer_puts(&q,")")!=0)goto fail;
    if(mysql_query(db,q.data)!=0)goto fail;
  }
  free(q.data);
  return 0;
fail:
  fprintf(stderr,"%s: %s history close failed: %s\n",PROGRAM_NAME,def->type,mysql_error(db));
  free(q.data);
  return -1;
}

static int delete_current_ids(MYSQL *db,const ApiDef *def,const IdList *ids) {
  Buffer q;
  size_t i;
  size_t n;

  memset(&q,0,sizeof(q));
  i=0;
  while(i<ids->n) {
    buffer_reset(&q);
    if(buffer_printf(&q,"DELETE FROM %s WHERE id IN (",def->table)!=0)goto fail;
    n=0;
    while(i<ids->n && n<BATCH_ROWS*2) {
      if(n && buffer_puts(&q,",")!=0)goto fail;
      if(buffer_printf(&q,"%llu",ids->v[i])!=0)goto fail;
      i++;
      n++;
    }
    if(buffer_puts(&q,")")!=0)goto fail;
    if(mysql_query(db,q.data)!=0)goto fail;
  }
  free(q.data);
  return 0;
fail:
  fprintf(stderr,"%s: %s delete failed: %s\n",PROGRAM_NAME,def->type,mysql_error(db));
  free(q.data);
  return -1;
}

static int import_endpoint(MYSQL *db,const ApiDef *def,const char *api_key) {
  char url[256];
  char stamp[40];
  Buffer json;
  Buffer current_q;
  Buffer history_q;
  JsonToken *tokens;
  int token_count;
  int data_token;
  int pos;
  int i;
  PdbRecord r;
  HistoryList history;
  IdList current;
  IdList seen;
  IdList close_ids;
  IdList removed_ids;
  const HistoryEntry *old;
  unsigned char hash[SHA256_DIGEST_LENGTH];
  size_t raw_len;
  ImportStats stats;
  int current_rows;
  int history_rows;
  int rc;

  memset(&json,0,sizeof(json));
  memset(&current_q,0,sizeof(current_q));
  memset(&history_q,0,sizeof(history_q));
  tokens=NULL;
  memset(&history,0,sizeof(history));
  memset(&current,0,sizeof(current));
  memset(&seen,0,sizeof(seen));
  memset(&close_ids,0,sizeof(close_ids));
  memset(&removed_ids,0,sizeof(removed_ids));
  memset(&stats,0,sizeof(stats));
  current_rows=0;
  history_rows=0;
  rc=-1;

  if(snprintf(url,sizeof(url),API_URL,def->type)<0)goto done;
  if(http_get(url,api_key,&json)!=0)goto done;
  if(parse_json(json.data,json.len,&tokens,&token_count)!=0)goto done;
  if(token_count<1 || tokens[0].type!=JSMN_OBJECT)goto done;
  data_token=object_get(json.data,tokens,0,"data");
  if(data_token<0 || tokens[data_token].type!=JSMN_ARRAY || tokens[data_token].size<=0) {
    fprintf(stderr,"%s: %s returned no data, refusing destructive sync\n",PROGRAM_NAME,def->type);
    goto done;
  }
  if(load_history(db,def,&history)!=0 || load_current_ids(db,def,&current)!=0 || db_timestamp(db,stamp,sizeof(stamp))!=0) {
    fprintf(stderr,"%s: cannot load %s database state\n",PROGRAM_NAME,def->type);
    goto done;
  }
  seen.v=(unsigned long long *)malloc((size_t)tokens[data_token].size*sizeof(unsigned long long));
  if(!seen.v)goto done;

  if(mysql_autocommit(db,0)!=0)goto done;
  pos=data_token+1;
  for(i=0;i<tokens[data_token].size;i++) {
    if(tokens[pos].type!=JSMN_OBJECT || parse_record(json.data,tokens,pos,&r)!=0) {
      fprintf(stderr,"%s: cannot parse %s object %d\n",PROGRAM_NAME,def->type,i);
      mysql_rollback(db);
      goto done;
    }
    seen.v[seen.n++]=r.id;
    stats.seen++;
    raw_len=(size_t)(r.raw_end-r.raw_start);
    SHA256((const unsigned char *)json.data+r.raw_start,raw_len,hash);
    old=history_find(&history,r.id);
    if(!old) {
      if(add_current(db,&current_q,def,&r,&current_rows)!=0 ||
          add_history(db,&history_q,def,&r,hash,json.data+r.raw_start,raw_len,stamp,&history_rows)!=0) {
        mysql_rollback(db);
        goto done;
      }
      stats.added++;
    } else if(memcmp(old->hash,hash,SHA256_DIGEST_LENGTH)!=0) {
      if(id_push(&close_ids,r.id)!=0 || add_current(db,&current_q,def,&r,&current_rows)!=0 ||
          add_history(db,&history_q,def,&r,hash,json.data+r.raw_start,raw_len,stamp,&history_rows)!=0) {
        mysql_rollback(db);
        goto done;
      }
      stats.changed++;
    } else if(!id_find(&current,r.id)) {
      if(add_current(db,&current_q,def,&r,&current_rows)!=0) {
        mysql_rollback(db);
        goto done;
      }
    }
    pos=token_skip(tokens,pos);
  }
  if(flush_current(db,&current_q,def,&current_rows)!=0 || flush_history(db,&history_q,def,&history_rows)!=0) {
    mysql_rollback(db);
    goto done;
  }

  qsort(seen.v,seen.n,sizeof(unsigned long long),cmp_id);
  for(i=0;i<(int)current.n;i++) {
    if(!id_find(&seen,current.v[i])) {
      if(id_push(&close_ids,current.v[i])!=0 || id_push(&removed_ids,current.v[i])!=0) {
        mysql_rollback(db);
        goto done;
      }
      stats.removed++;
    }
  }
  if(close_history_ids(db,def,&close_ids,stamp)!=0 || delete_current_ids(db,def,&removed_ids)!=0) {
    mysql_rollback(db);
    goto done;
  }
  if(mysql_commit(db)!=0) {
    mysql_rollback(db);
    goto done;
  }
  mysql_autocommit(db,1);
  printf("%s: seen=%lu added=%lu changed=%lu removed=%lu\n",
    def->type,stats.seen,stats.added,stats.changed,stats.removed);
  fflush(stdout);
  rc=0;

done:
  mysql_autocommit(db,1);
  free(json.data);
  free(current_q.data);
  free(history_q.data);
  free(tokens);
  free(history.v);
  free(current.v);
  free(seen.v);
  free(close_ids.v);
  free(removed_ids.v);
  return rc;
}

static int command_dbcheck(void) {
  DbConfig cfg;
  MYSQL *db;
  MYSQL_RES *res;
  MYSQL_ROW row;
  int count;

  if(load_config(&cfg)!=0)return 1;
  db=db_connect(&cfg);
  if(!db)return 1;
  if(mysql_query(db,"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()")!=0) {
    mysql_close(db);
    return 1;
  }
  res=mysql_store_result(db);
  row=res ? mysql_fetch_row(res) : NULL;
  count=row && row[0] ? atoi(row[0]) : -1;
  if(res)mysql_free_result(res);
  printf("database: connected to %s:%u/%s\n",cfg.host,cfg.port,cfg.name);
  printf("server: %s\n",mysql_get_server_info(db));
  printf("schema: %d tables\n",count);
  mysql_close(db);
  return count>=EXPECTED_TABLES ? 0 : 1;
}

static int command_update(void) {
  static const ApiDef defs[]={
    {"org","organization_current"},
    {"fac","facility_current"},
    {"ix","ix_current"},
    {"ixlan","ixlan_current"},
    {"ixpfx","ixpfx_current"},
    {"net","network_current"},
    {"ixfac","ixfac_current"},
    {"netfac","netfac_current"},
    {"netixlan","netixlan_current"}
  };
  DbConfig cfg;
  MYSQL *db;
  size_t i;
  int rc;

  if(load_config(&cfg)!=0)return 1;
  db=db_connect(&cfg);
  if(!db)return 1;
  rc=0;
  for(i=0;i<sizeof(defs)/sizeof(defs[0]);i++) {
    if(import_endpoint(db,&defs[i],cfg.api_key)!=0) {
      rc=1;
      break;
    }
    if(i+1<sizeof(defs)/sizeof(defs[0]))sleep(1);
  }
  mysql_close(db);
  return rc;
}

static int command_status(void) {
  static const ApiDef defs[]={
    {"org","organization_current"},
    {"fac","facility_current"},
    {"ix","ix_current"},
    {"ixlan","ixlan_current"},
    {"ixpfx","ixpfx_current"},
    {"net","network_current"},
    {"ixfac","ixfac_current"},
    {"netfac","netfac_current"},
    {"netixlan","netixlan_current"}
  };
  DbConfig cfg;
  MYSQL *db;
  MYSQL_RES *res;
  MYSQL_ROW row;
  char query[512];
  size_t i;
  unsigned long long current_count;
  unsigned long long history_open;
  unsigned long long history_total;

  if(load_config(&cfg)!=0)return 1;
  db=db_connect(&cfg);
  if(!db)return 1;

  printf("type       current     history_open     history_total\n");
  printf("---------- ----------- ---------------- ----------------\n");
  for(i=0;i<sizeof(defs)/sizeof(defs[0]);i++) {
    snprintf(query,sizeof(query),
      "SELECT (SELECT COUNT(*) FROM %s),"
      "(SELECT COUNT(*) FROM object_history WHERE object_type='%s' AND valid_to IS NULL),"
      "(SELECT COUNT(*) FROM object_history WHERE object_type='%s')",
      defs[i].table,defs[i].type,defs[i].type);
    if(mysql_query(db,query)!=0) {
      fprintf(stderr,"%s: status query failed for %s: %s\n",
        PROGRAM_NAME,defs[i].type,mysql_error(db));
      mysql_close(db);
      return 1;
    }
    res=mysql_store_result(db);
    row=res ? mysql_fetch_row(res) : NULL;
    if(!row || !row[0] || !row[1] || !row[2]) {
      if(res)mysql_free_result(res);
      mysql_close(db);
      return 1;
    }
    current_count=strtoull(row[0],NULL,10);
    history_open=strtoull(row[1],NULL,10);
    history_total=strtoull(row[2],NULL,10);
    printf("%-10s %11llu %16llu %16llu\n",
      defs[i].type,current_count,history_open,history_total);
    mysql_free_result(res);
  }
  mysql_close(db);
  return 0;
}

static int mkdir_one(const char *path) {
  if(mkdir(path,0755)==0 || errno==EEXIST)return 0;
  fprintf(stderr,"%s: cannot create directory %s: %s\n",PROGRAM_NAME,path,strerror(errno));
  return -1;
}

static int mkdir_tree(const char *path) {
  char tmp[PATH_LEN];
  char *p;
  size_t len;

  len=strlen(path);
  if(len==0 || len>=sizeof(tmp))return -1;
  memcpy(tmp,path,len+1);
  if(len>1 && tmp[len-1]=='/')tmp[len-1]='\0';
  for(p=tmp+1;*p;p++) {
    if(*p=='/') {
      *p='\0';
      if(mkdir_one(tmp)!=0)return -1;
      *p='/';
    }
  }
  return mkdir_one(tmp);
}

static void html_escape(FILE *fp,const char *s) {
  for(;*s;s++) {
    if(*s=='&')fputs("&amp;",fp);
    else if(*s=='<')fputs("&lt;",fp);
    else if(*s=='>')fputs("&gt;",fp);
    else if(*s=='\"')fputs("&quot;",fp);
    else if(*s=='\'')fputs("&#39;",fp);
    else fputc((unsigned char)*s,fp);
  }
}

static void format_capacity(unsigned long long mbps,char *buf,size_t size) {
  if(mbps>=1000000ULL)snprintf(buf,size,"%.2f Tbps",(double)mbps/1000000.0);
  else if(mbps>=1000ULL)snprintf(buf,size,"%.2f Gbps",(double)mbps/1000.0);
  else snprintf(buf,size,"%llu Mbps",mbps);
}

static void html_header(FILE *fp,const char *title,const char *home) {
  time_t now;
  struct tm *tmv;
  char stamp[64];
  const char *root;

  now=time(NULL);
  tmv=gmtime(&now);
  if(tmv)strftime(stamp,sizeof(stamp),"%Y-%m-%d %H:%M UTC",tmv);
  else strcpy(stamp,"unknown time");
  root=home && *home ? home : "index.html";
  fputs("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",fp);
  fputs("<style>:root{--green:#16713f;--green2:#0f5d34;--green3:#e8f4ed;--ink:#1e2b24;--muted:#617069;--line:#d9e2dc;--soft:#f6f8f7;--white:#fff}*{box-sizing:border-box}body{margin:0;background:var(--soft);color:var(--ink);font-family:Arial,Helvetica,sans-serif;line-height:1.42}.top{position:sticky;top:0;z-index:20;background:linear-gradient(135deg,var(--green2),var(--green));color:var(--white);padding:.72rem 1.35rem .78rem;box-shadow:0 2px 8px #0003}.top a{color:var(--white)}.headrow{display:flex;align-items:center;gap:1rem;flex-wrap:wrap}.brand{font-size:1.2rem;font-weight:800;white-space:nowrap}.pagetitle{font-size:1rem;font-weight:600;opacity:.95;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1;min-width:12rem}.headnav{display:flex;gap:.45rem;flex-wrap:wrap}.headnav a{border:1px solid #ffffff66;border-radius:999px;padding:.25rem .62rem;background:#ffffff12}.disclaimer{margin-top:.48rem;border-top:1px solid #ffffff3a;padding-top:.45rem;font-size:.76rem;line-height:1.35;opacity:.93}.generated{font-size:.72rem;opacity:.72;margin-top:.2rem}.wrap{max-width:1900px;margin:auto;padding:1.35rem 1.5rem 2.5rem}h1{margin:.15rem 0;font-size:1.8rem}h2{margin-top:1.8rem;color:var(--green2)}h3{color:var(--green2)}a{color:var(--green2);text-decoration:none;font-weight:600}a:hover{text-decoration:underline}.meta{opacity:.85;font-size:.88rem}.nav{display:flex;gap:.55rem;flex-wrap:wrap;margin:1rem 0}.nav a,.pill{display:inline-block;border:1px solid #b8d2c1;background:var(--white);border-radius:999px;padding:.34rem .7rem}.notice{background:#fff;border-left:4px solid var(--green);padding:.75rem 1rem;margin:1rem 0;box-shadow:0 1px 3px #0001}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(175px,1fr));gap:.75rem;margin:1rem 0}.card{background:#fff;border:1px solid var(--line);border-radius:9px;padding:.85rem 1rem;box-shadow:0 1px 3px #0001}.card .value{font-size:1.5rem;font-weight:700;color:var(--green2);white-space:nowrap}.card .label{font-size:.85rem;color:var(--muted)}.tablewrap{overflow:auto;background:#fff;border:1px solid var(--line);border-radius:9px;box-shadow:0 1px 4px #0001}table{border-collapse:separate;border-spacing:0;width:100%;font-size:.91rem}th,td{padding:.5rem .6rem;border-bottom:1px solid var(--line);vertical-align:top}th{position:sticky;top:0;z-index:2;background:var(--green);color:#fff;text-align:left;white-space:nowrap}tbody tr:nth-child(even){background:#f8fbf9}tbody tr:hover{background:var(--green3)}td.num,th.num{text-align:right;white-space:nowrap}.rank{display:inline-block;min-width:2.1rem;text-align:center;font-weight:700;color:var(--green2)}.asnlist{min-width:300px;max-width:620px;font-size:.84rem;line-height:1.5}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.45rem}.grid a{background:#fff;border:1px solid var(--line);padding:.45rem .6rem;border-radius:6px}.chart{background:#fff;border:1px solid var(--line);border-radius:9px;padding:1rem;margin:1rem 0;box-shadow:0 1px 4px #0001}.chartrow{display:grid;grid-template-columns:minmax(150px,280px) minmax(160px,1fr) 100px;gap:.65rem;align-items:center;margin:.38rem 0}.chartlabel{white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.track{height:17px;background:#e7ece9;border-radius:4px;overflow:hidden}.bar{height:100%;background:linear-gradient(90deg,var(--green),#4b9b6d);min-width:2px}.chartvalue{text-align:right;font-variant-numeric:tabular-nums;font-size:.88rem}.small{font-size:.86rem;color:var(--muted)}.good{color:var(--green2);font-weight:700}.footer{margin-top:2rem;padding-top:1rem;border-top:1px solid var(--line);color:var(--muted);font-size:.82rem}@media(max-width:760px){.top{padding:.6rem .7rem}.brand{font-size:1.05rem}.pagetitle{order:3;flex-basis:100%;font-size:.88rem}.disclaimer{font-size:.69rem}.wrap{padding:1rem .65rem}.chartrow{grid-template-columns:120px 1fr 80px}table{font-size:.82rem}th,td{padding:.42rem}.asnlist{min-width:220px}}</style>",fp);
  fputs("<title>",fp);
  html_escape(fp,title);
  fputs("</title></head><body><header class=\"top\"><div class=\"headrow\"><div class=\"brand\"><a href=\"",fp);
  fputs(root,fp);
  fprintf(fp,"\">PeeringDB Analysis %s</a></div>",PROGRAM_VERSION);
  if(strcmp(title,"PeeringDB Analysis")) {
    fputs("<div class=\"pagetitle\">",fp);
    html_escape(fp,title);
    fputs("</div>",fp);
  } else fputs("<div class=\"pagetitle\"></div>",fp);
  fputs("<nav class=\"headnav\"><a href=\"",fp);
  fputs(root,fp);
  fputs("\">Home</a></nav></div>",fp);
  fputs("<div class=\"disclaimer\">Data are sourced from PeeringDB and processed by PeeringDB Analysis. We do not accept responsibility for any use of the information shown and do not guarantee its correctness, completeness or up-to-dateness. Contact: <a href=\"mailto:gianluca@mazzini.org\">gianluca@mazzini.org</a></div>",fp);
  fprintf(fp,"<div class=\"generated\">Generated %s by %s %s</div></header><main class=\"wrap\">",stamp,PROGRAM_NAME,PROGRAM_VERSION);
}

static void html_footer(FILE *fp) {
  fputs("<div class=\"footer\">Source: PeeringDB. Declared speeds are PeeringDB data and are not measured Internet traffic.</div></main></body></html>\n",fp);
}

static double metric_top_pct(const IxMetric *m) {
  if(!m->total_capacity)return 0.0;
  return (double)m->top_capacity*100.0/(double)m->total_capacity;
}

static int cmp_metric_id(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->id<y->id)return -1;
  if(x->id>y->id)return 1;
  return 0;
}

static int cmp_metric_asn(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->asn_count>y->asn_count)return -1;
  if(x->asn_count<y->asn_count)return 1;
  return strcmp(x->name,y->name);
}

static int cmp_metric_capacity(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->total_capacity>y->total_capacity)return -1;
  if(x->total_capacity<y->total_capacity)return 1;
  return strcmp(x->name,y->name);
}

static int cmp_metric_v4(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->v4_capacity>y->v4_capacity)return -1;
  if(x->v4_capacity<y->v4_capacity)return 1;
  return strcmp(x->name,y->name);
}

static int cmp_metric_v6(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->v6_capacity>y->v6_capacity)return -1;
  if(x->v6_capacity<y->v6_capacity)return 1;
  return strcmp(x->name,y->name);
}

static int cmp_metric_ports(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->conn_400g>y->conn_400g)return -1;
  if(x->conn_400g<y->conn_400g)return 1;
  if(x->conn_100g>y->conn_100g)return -1;
  if(x->conn_100g<y->conn_100g)return 1;
  if(x->total_capacity>y->total_capacity)return -1;
  if(x->total_capacity<y->total_capacity)return 1;
  return strcmp(x->name,y->name);
}

static int cmp_metric_facilities(const void *a,const void *b) {
  const IxMetric *x;
  const IxMetric *y;

  x=(const IxMetric *)a;
  y=(const IxMetric *)b;
  if(x->facility_count>y->facility_count)return -1;
  if(x->facility_count<y->facility_count)return 1;
  if(x->asn_count>y->asn_count)return -1;
  if(x->asn_count<y->asn_count)return 1;
  return strcmp(x->name,y->name);
}

static int cmp_country(const void *a,const void *b) {
  return strcmp((const char *)a,(const char *)b);
}

static int cmp_continent(const void *a,const void *b) {
  return strcmp((const char *)a,(const char *)b);
}

static int load_metrics(MYSQL *db,IxMetric **out,size_t *out_n) {
  const char *sql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  IxMetric *m;
  size_t n;
  size_t i;

  sql="SELECT i.id,i.name,i.city,i.country,i.continent,a.asn_count,a.v4_asns,a.v6_asns,a.dual_asns,"
      "a.connections,a.total_speed,a.v4_speed,a.v6_speed,a.c100,a.c400,a.c800,"
      "COALESCE(f.facilities,0),COALESCE(l.lans,0) "
      "FROM ix_current i JOIN ("
      "SELECT ix_id,COUNT(*) asn_count,SUM(has4) v4_asns,SUM(has6) v6_asns,"
      "SUM(CASE WHEN has4=1 AND has6=1 THEN 1 ELSE 0 END) dual_asns,"
      "SUM(conn_count) connections,SUM(total_speed) total_speed,SUM(v4_speed) v4_speed,SUM(v6_speed) v6_speed,"
      "SUM(c100) c100,SUM(c400) c400,SUM(c800) c800 FROM ("
      "SELECT ix_id,asn,MAX(ipaddr4 IS NOT NULL) has4,MAX(ipaddr6 IS NOT NULL) has6,COUNT(*) conn_count,"
      "SUM(speed_mbps) total_speed,SUM(CASE WHEN ipaddr4 IS NOT NULL THEN speed_mbps ELSE 0 END) v4_speed,"
      "SUM(CASE WHEN ipaddr6 IS NOT NULL THEN speed_mbps ELSE 0 END) v6_speed,"
      "SUM(speed_mbps>=100000) c100,SUM(speed_mbps>=400000) c400,SUM(speed_mbps>=800000) c800 "
      "FROM netixlan_current WHERE status='ok' AND operational=1 AND speed_mbps>0 GROUP BY ix_id,asn) p GROUP BY ix_id) a ON a.ix_id=i.id "
      "LEFT JOIN (SELECT ix_id,COUNT(DISTINCT fac_id) facilities FROM ixfac_current WHERE status='ok' GROUP BY ix_id) f ON f.ix_id=i.id "
      "LEFT JOIN (SELECT ix_id,COUNT(*) lans FROM ixlan_current WHERE status='ok' GROUP BY ix_id) l ON l.ix_id=i.id "
      "WHERE i.status='ok' ORDER BY i.id";
  if(mysql_query(db,sql)!=0) {
    fprintf(stderr,"%s: metric query failed: %s\n",PROGRAM_NAME,mysql_error(db));
    return -1;
  }
  res=mysql_store_result(db);
  if(!res)return -1;
  n=(size_t)mysql_num_rows(res);
  m=(IxMetric *)calloc(n,sizeof(IxMetric));
  if(n && !m) {
    mysql_free_result(res);
    return -1;
  }
  i=0;
  while((row=mysql_fetch_row(res))!=NULL) {
    m[i].id=strtoull(row[0],NULL,10);
    copy_value(m[i].name,sizeof(m[i].name),row[1] ? row[1] : "","ix name");
    copy_value(m[i].city,sizeof(m[i].city),row[2] ? row[2] : "","ix city");
    copy_value(m[i].country,sizeof(m[i].country),row[3] ? row[3] : "","ix country");
    copy_value(m[i].continent,sizeof(m[i].continent),row[4] ? row[4] : "","ix continent");
    m[i].asn_count=strtoull(row[5] ? row[5] : "0",NULL,10);
    m[i].v4_asn_count=strtoull(row[6] ? row[6] : "0",NULL,10);
    m[i].v6_asn_count=strtoull(row[7] ? row[7] : "0",NULL,10);
    m[i].dual_asn_count=strtoull(row[8] ? row[8] : "0",NULL,10);
    m[i].connections=strtoull(row[9] ? row[9] : "0",NULL,10);
    m[i].total_capacity=strtoull(row[10] ? row[10] : "0",NULL,10);
    m[i].v4_capacity=strtoull(row[11] ? row[11] : "0",NULL,10);
    m[i].v6_capacity=strtoull(row[12] ? row[12] : "0",NULL,10);
    m[i].conn_100g=strtoull(row[13] ? row[13] : "0",NULL,10);
    m[i].conn_400g=strtoull(row[14] ? row[14] : "0",NULL,10);
    m[i].conn_800g=strtoull(row[15] ? row[15] : "0",NULL,10);
    m[i].facility_count=strtoull(row[16] ? row[16] : "0",NULL,10);
    m[i].lan_count=strtoull(row[17] ? row[17] : "0",NULL,10);
    i++;
  }
  mysql_free_result(res);
  *out=m;
  *out_n=i;
  return 0;
}

static int load_top_asns(MYSQL *db,IxMetric *m,size_t n) {
  const char *sql;
  MYSQL_RES *res;
  MYSQL_ROW row;
  unsigned long long ix_id;
  unsigned long long asn;
  unsigned long long cap;
  size_t i;
  size_t used;
  char item[512];
  const char *name;

  qsort(m,n,sizeof(IxMetric),cmp_metric_id);
  sql="SELECT nx.ix_id,nx.asn,COALESCE(n.name,''),SUM(nx.speed_mbps) total "
      "FROM netixlan_current nx LEFT JOIN network_current n ON n.id=nx.net_id "
      "WHERE nx.status='ok' AND nx.operational=1 AND nx.speed_mbps>0 "
      "GROUP BY nx.ix_id,nx.asn,n.name ORDER BY nx.ix_id,total DESC,nx.asn";
  if(mysql_query(db,sql)!=0) {
    fprintf(stderr,"%s: top ASN query failed: %s\n",PROGRAM_NAME,mysql_error(db));
    return -1;
  }
  res=mysql_use_result(db);
  if(!res)return -1;
  i=0;
  while((row=mysql_fetch_row(res))!=NULL) {
    ix_id=strtoull(row[0],NULL,10);
    while(i<n && m[i].id<ix_id)i++;
    if(i>=n)break;
    if(m[i].id!=ix_id || m[i].top_count>=20)continue;
    asn=strtoull(row[1],NULL,10);
    name=row[2] ? row[2] : "";
    cap=strtoull(row[3] ? row[3] : "0",NULL,10);
    snprintf(item,sizeof(item),"AS%llu%s%s%s",asn,*name ? " (" : "",name,*name ? ")" : "");
    used=strlen(m[i].top20_asn);
    if(used && used+2<sizeof(m[i].top20_asn)) {
      m[i].top20_asn[used++]=',';
      m[i].top20_asn[used++]=' ';
      m[i].top20_asn[used]='\0';
    }
    if(used+strlen(item)+1<sizeof(m[i].top20_asn))strcat(m[i].top20_asn,item);
    if(m[i].top_count<10) {
      used=strlen(m[i].top_asn);
      if(used && used+2<sizeof(m[i].top_asn)) {
        m[i].top_asn[used++]=',';
        m[i].top_asn[used++]=' ';
        m[i].top_asn[used]='\0';
      }
      if(used+strlen(item)+1<sizeof(m[i].top_asn))strcat(m[i].top_asn,item);
      m[i].top_capacity+=cap;
    }
    m[i].top_count++;
  }
  mysql_free_result(res);
  return 0;
}

static int metric_match(const IxMetric *m,int filter,const char *value) {
  if(filter==1)return !strcmp(m->country,value);
  if(filter==2)return !strcmp(m->continent,value);
  return 1;
}

static double chart_value(const IxMetric *m,int mode) {
  if(mode==0)return (double)m->asn_count;
  if(mode==1)return (double)m->total_capacity;
  if(mode==2)return (double)m->v4_capacity;
  if(mode==3)return (double)m->v6_capacity;
  if(mode==5)return (double)m->conn_400g;
  if(mode==6)return (double)m->facility_count;
  return 0.0;
}

static void chart_value_text(const IxMetric *m,int mode,char *buf,size_t size) {
  if(mode==0)snprintf(buf,size,"%llu",m->asn_count);
  else if(mode==1)format_capacity(m->total_capacity,buf,size);
  else if(mode==2)format_capacity(m->v4_capacity,buf,size);
  else if(mode==3)format_capacity(m->v6_capacity,buf,size);
  else if(mode==5)snprintf(buf,size,"%llu",m->conn_400g);
  else if(mode==6)snprintf(buf,size,"%llu",m->facility_count);
  else strcpy(buf,"-");
}

static void write_chart(FILE *fp,IxMetric *m,size_t n,int filter,const char *value,int mode) {
  size_t i;
  unsigned int shown;
  double maxv;
  double v;
  double pct;
  char text[64];

  maxv=0.0;
  shown=0;
  for(i=0;i<n && shown<15;i++) {
    if(!metric_match(&m[i],filter,value))continue;
    v=chart_value(&m[i],mode);
    if(v>maxv)maxv=v;
    shown++;
  }
  if(shown<2 || maxv<=0.0)return;
  fputs("<div class=\"chart\"><h2>Top view</h2>",fp);
  shown=0;
  for(i=0;i<n && shown<15;i++) {
    if(!metric_match(&m[i],filter,value))continue;
    v=chart_value(&m[i],mode);
    pct=v*100.0/maxv;
    chart_value_text(&m[i],mode,text,sizeof(text));
    fputs("<div class=\"chartrow\"><div class=\"chartlabel\" title=\"",fp);
    html_escape(fp,m[i].name);
    fputs("\">",fp);
    html_escape(fp,m[i].name);
    fprintf(fp,"</div><div class=\"track\"><div class=\"bar\" style=\"width:%.2f%%\"></div></div><div class=\"chartvalue\">%s</div></div>",pct,text);
    shown++;
  }
  fputs("</div>",fp);
}

static void write_rank_cards(FILE *fp,IxMetric *m,size_t n,int filter,const char *value) {
  size_t i;
  unsigned long long ixcount;
  unsigned long long members;
  unsigned long long connections;
  unsigned long long speed;
  char cap[64];

  ixcount=0;
  members=0;
  connections=0;
  speed=0;
  for(i=0;i<n;i++) {
    if(!metric_match(&m[i],filter,value))continue;
    ixcount++;
    members+=m[i].asn_count;
    connections+=m[i].connections;
    speed+=m[i].total_capacity;
  }
  format_capacity(speed,cap,sizeof(cap));
  fputs("<div class=\"cards\">",fp);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Internet Exchanges</div></div>",ixcount);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Member presences</div></div>",members);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Operational connections</div></div>",connections);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%s</div><div class=\"label\">Declared port speed</div></div>",cap);
  fputs("</div>",fp);
}

static void write_methodology(FILE *fp) {
  fputs("<div class=\"notice small\"><strong>Method:</strong> only PeeringDB connection records with <code>status=ok</code>, <code>operational=true</code> and a positive declared speed are counted. No historical 100 Mbps minimum or 10 Tbps maximum is applied. Total declared port speed counts each connection once. IPv4 and IPv6 speed are protocol views and may overlap on dual-stack connections; they must not be added together as physical capacity.</div>",fp);
}

static void write_ix_link(FILE *fp,const IxMetric *m) {
  fprintf(fp,"<a href=\"../ix/%llu.html\">",m->id);
  html_escape(fp,m->name);
  fputs("</a>",fp);
}

static int write_rank_page(const char *path,const char *title,const char *home,
    IxMetric *m,size_t n,int filter,const char *value,int mode) {
  FILE *fp;
  size_t i;
  unsigned long rank;
  unsigned long long avg;
  char total[64];
  char v4[64];
  char v6[64];
  char avgtext[64];
  char top[64];

  fp=fopen(path,"w");
  if(!fp) {
    fprintf(stderr,"%s: cannot write %s: %s\n",PROGRAM_NAME,path,strerror(errno));
    return -1;
  }
  html_header(fp,title,home);
  write_rank_cards(fp,m,n,filter,value);
  write_methodology(fp);
  if(filter==0)write_chart(fp,m,n,filter,value,mode);
  fputs("<div class=\"tablewrap\"><table><thead><tr><th class=\"num\">Rank</th><th>Internet Exchange</th>",fp);
  if(mode==0)fputs("<th class=\"num\">Members</th><th class=\"num\">Connections</th><th class=\"num\">Total speed</th><th class=\"num\">IPv4 speed</th><th class=\"num\">IPv6 speed</th><th class=\"num\">IPv6 members</th><th>Top 10 ASN</th><th class=\"num\">Top 10 speed</th>",fp);
  else if(mode==1)fputs("<th class=\"num\">Total speed</th><th class=\"num\">Members</th><th class=\"num\">Connections</th><th class=\"num\">Avg connection</th><th class=\"num\">100G+</th><th class=\"num\">400G+</th><th class=\"num\">800G+</th><th class=\"num\">Top 10 share</th>",fp);
  else if(mode==2)fputs("<th class=\"num\">IPv4 speed</th><th class=\"num\">IPv4 members</th><th class=\"num\">Members</th><th class=\"num\">Total speed</th><th class=\"num\">IPv6 speed</th>",fp);
  else if(mode==3)fputs("<th class=\"num\">IPv6 speed</th><th class=\"num\">IPv6 members</th><th class=\"num\">Members</th><th class=\"num\">Dual stack</th><th class=\"num\">Total speed</th>",fp);
  else if(mode==5)fputs("<th class=\"num\">400G+</th><th class=\"num\">800G+</th><th class=\"num\">100G+</th><th class=\"num\">Connections</th><th class=\"num\">Avg connection</th><th class=\"num\">Total speed</th><th class=\"num\">Members</th>",fp);
  else fputs("<th class=\"num\">Facilities</th><th class=\"num\">LANs</th><th class=\"num\">Members</th><th class=\"num\">Total speed</th>",fp);
  fputs("<th>City</th><th>Country</th></tr></thead><tbody>",fp);
  rank=0;
  for(i=0;i<n;i++) {
    if(!metric_match(&m[i],filter,value))continue;
    rank++;
    format_capacity(m[i].total_capacity,total,sizeof(total));
    format_capacity(m[i].v4_capacity,v4,sizeof(v4));
    format_capacity(m[i].v6_capacity,v6,sizeof(v6));
    format_capacity(m[i].top_capacity,top,sizeof(top));
    avg=m[i].connections ? m[i].total_capacity/m[i].connections : 0;
    format_capacity(avg,avgtext,sizeof(avgtext));
    fprintf(fp,"<tr><td class=\"num\"><span class=\"rank\">%lu</span></td><td>",rank);
    write_ix_link(fp,&m[i]);
    if(mode==0) {
      fprintf(fp,"</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%s</td><td class=\"num\">%s</td><td class=\"num\">%s</td><td class=\"num\">%llu</td><td class=\"asnlist\">",m[i].asn_count,m[i].connections,total,v4,v6,m[i].v6_asn_count);
      html_escape(fp,m[i].top_asn);
      fprintf(fp,"</td><td class=\"num\">%s</td>",top);
    } else if(mode==1)fprintf(fp,"</td><td class=\"num\">%s</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%s</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%.1f%%</td>",total,m[i].asn_count,m[i].connections,avgtext,m[i].conn_100g,m[i].conn_400g,m[i].conn_800g,metric_top_pct(&m[i]));
    else if(mode==2)fprintf(fp,"</td><td class=\"num\">%s</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%s</td><td class=\"num\">%s</td>",v4,m[i].v4_asn_count,m[i].asn_count,total,v6);
    else if(mode==3)fprintf(fp,"</td><td class=\"num\">%s</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%s</td>",v6,m[i].v6_asn_count,m[i].asn_count,m[i].dual_asn_count,total);
    else if(mode==5)fprintf(fp,"</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%s</td><td class=\"num\">%s</td><td class=\"num\">%llu</td>",m[i].conn_400g,m[i].conn_800g,m[i].conn_100g,m[i].connections,avgtext,total,m[i].asn_count);
    else fprintf(fp,"</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%llu</td><td class=\"num\">%s</td>",m[i].facility_count,m[i].lan_count,m[i].asn_count,total);
    fputs("<td>",fp);
    html_escape(fp,m[i].city);
    fputs("</td><td>",fp);
    html_escape(fp,m[i].country);
    fputs("</td></tr>",fp);
  }
  fputs("</tbody></table></div>",fp);
  html_footer(fp);
  fclose(fp);
  return 0;
}

static void slugify(const char *src,char *dst,size_t size) {
  size_t out;
  int dash;
  unsigned char c;

  out=0;
  dash=0;
  while(*src && out+1<size) {
    c=(unsigned char)*src++;
    if(isalnum(c)) {
      dst[out++]=(char)c;
      dash=0;
    } else if(!dash && out>0 && out+1<size) {
      dst[out++]='-';
      dash=1;
    }
  }
  while(out>0 && dst[out-1]=='-')out--;
  dst[out]='\0';
}

static int list_has(char *base,size_t count,size_t width,const char *value) {
  size_t i;

  for(i=0;i<count;i++)if(!strcmp(base+i*width,value))return 1;
  return 0;
}

static int write_ix_page(const char *path,const IxMetric *m) {
  FILE *fp;
  char total[64];
  char v4[64];
  char v6[64];
  char avg[64];
  unsigned long long average;

  fp=fopen(path,"w");
  if(!fp)return -1;
  html_header(fp,m->name,"../index.html");
  format_capacity(m->total_capacity,total,sizeof(total));
  format_capacity(m->v4_capacity,v4,sizeof(v4));
  format_capacity(m->v6_capacity,v6,sizeof(v6));
  average=m->connections ? m->total_capacity/m->connections : 0;
  format_capacity(average,avg,sizeof(avg));
  fputs("<div class=\"cards\">",fp);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Members (ASNs)</div></div>",m->asn_count);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%s</div><div class=\"label\">Declared port speed</div></div>",total);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Operational connections</div></div>",m->connections);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Facilities</div></div>",m->facility_count);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Peering LANs</div></div>",m->lan_count);
  fputs("</div>",fp);
  write_methodology(fp);
  fputs("<h2>Protocol view</h2><div class=\"tablewrap\"><table><thead><tr><th>Metric</th><th class=\"num\">Value</th></tr></thead><tbody>",fp);
  fprintf(fp,"<tr><td>IPv4 members</td><td class=\"num\">%llu</td></tr><tr><td>IPv6 members</td><td class=\"num\">%llu</td></tr><tr><td>Dual-stack members</td><td class=\"num\">%llu</td></tr>",m->v4_asn_count,m->v6_asn_count,m->dual_asn_count);
  fprintf(fp,"<tr><td>IPv4 declared speed</td><td class=\"num\">%s</td></tr><tr><td>IPv6 declared speed</td><td class=\"num\">%s</td></tr></tbody></table></div>",v4,v6);
  fputs("<h2>Connection profile</h2><div class=\"tablewrap\"><table><thead><tr><th>Metric</th><th class=\"num\">Value</th></tr></thead><tbody>",fp);
  fprintf(fp,"<tr><td>Average declared speed per connection</td><td class=\"num\">%s</td></tr><tr><td>100G+ connections</td><td class=\"num\">%llu</td></tr><tr><td>400G+ connections</td><td class=\"num\">%llu</td></tr><tr><td>800G+ connections</td><td class=\"num\">%llu</td></tr><tr><td>Top 10 ASN share of declared speed</td><td class=\"num\">%.1f%%</td></tr></tbody></table></div>",avg,m->conn_100g,m->conn_400g,m->conn_800g,metric_top_pct(m));
  fputs("<h2>Top 20 ASN by declared speed</h2><div class=\"notice\">",fp);
  html_escape(fp,m->top20_asn);
  fputs("</div><h2>Location</h2><p>",fp);
  html_escape(fp,m->city);
  if(m->city[0] && m->country[0])fputs(", ",fp);
  html_escape(fp,m->country);
  fputs("</p>",fp);
  html_footer(fp);
  fclose(fp);
  return 0;
}

static int write_index(const char *path,char countries[][COUNTRY_LEN],size_t nc,
    char continents[][CONTINENT_LEN],size_t nt,IxMetric *m,size_t n) {
  FILE *fp;
  size_t i;
  unsigned long long members;
  unsigned long long connections;
  unsigned long long speed;
  char cap[64];
  char slug[128];

  fp=fopen(path,"w");
  if(!fp)return -1;
  members=0;
  connections=0;
  speed=0;
  for(i=0;i<n;i++) {
    members+=m[i].asn_count;
    connections+=m[i].connections;
    speed+=m[i].total_capacity;
  }
  format_capacity(speed,cap,sizeof(cap));
  html_header(fp,"PeeringDB Analysis",NULL);
  fputs("<div class=\"notice\">Ranks Internet Exchanges from the current PeeringDB dataset. Version 3 modernises the original 2016 methodology and adds connection-speed and facility metrics while retaining a fully static site.</div>",fp);
  fputs("<div class=\"cards\">",fp);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%lu</div><div class=\"label\">Internet Exchanges with operational members</div></div>",(unsigned long)n);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Member presences</div></div>",members);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%llu</div><div class=\"label\">Operational connections</div></div>",connections);
  fprintf(fp,"<div class=\"card\"><div class=\"value\">%s</div><div class=\"label\">Declared port speed</div></div>",cap);
  fputs("</div>",fp);
  write_methodology(fp);
  fputs("<h2 id=\"rankings\">World rankings</h2><div class=\"grid\"><a href=\"rank/asn.html\">Members (ASNs)</a><a href=\"rank/capacity.html\">Total declared speed</a><a href=\"rank/ipv4.html\">IPv4 declared speed</a><a href=\"rank/ipv6.html\">IPv6 declared speed</a><a href=\"rank/ports.html\">High-speed connections</a><a href=\"rank/facilities.html\">Facility footprint</a></div>",fp);
  fputs("<h2>Continents</h2><div class=\"grid\">",fp);
  for(i=0;i<nt;i++) {
    slugify(continents[i],slug,sizeof(slug));
    fprintf(fp,"<a href=\"continent/%s.html\">",slug);
    html_escape(fp,continents[i]);
    fputs("</a>",fp);
  }
  fputs("</div><h2>Countries</h2><div class=\"grid\">",fp);
  for(i=0;i<nc;i++)fprintf(fp,"<a href=\"country/%s.html\">%s</a>",countries[i],countries[i]);
  fputs("</div>",fp);
  html_footer(fp);
  fclose(fp);
  return 0;
}

static int command_generate(const char *outdir) {
  DbConfig cfg;
  MYSQL *db;
  IxMetric *m;
  size_t n;
  char countries[256][COUNTRY_LEN];
  char continents[64][CONTINENT_LEN];
  size_t nc;
  size_t nt;
  size_t i;
  char path[PATH_LEN];
  char dir[PATH_LEN];
  char title[512];
  char slug[128];
  unsigned long files;
  int rc;

  m=NULL;
  n=0;
  nc=0;
  nt=0;
  files=0;
  rc=1;
  if(load_config(&cfg)!=0)return 1;
  db=db_connect(&cfg);
  if(!db)return 1;
  if(load_metrics(db,&m,&n)!=0 || load_top_asns(db,m,n)!=0)goto done;
  for(i=0;i<n;i++) {
    if(m[i].country[0] && nc<256 && !list_has((char *)countries,nc,COUNTRY_LEN,m[i].country)) {
      copy_value(countries[nc],COUNTRY_LEN,m[i].country,"country");
      nc++;
    }
    if(m[i].continent[0] && nt<64 && !list_has((char *)continents,nt,CONTINENT_LEN,m[i].continent)) {
      copy_value(continents[nt],CONTINENT_LEN,m[i].continent,"continent");
      nt++;
    }
  }
  qsort(countries,nc,COUNTRY_LEN,cmp_country);
  qsort(continents,nt,CONTINENT_LEN,cmp_continent);
  if(mkdir_tree(outdir)!=0)goto done;
  snprintf(dir,sizeof(dir),"%s/rank",outdir);
  if(mkdir_tree(dir)!=0)goto done;
  snprintf(dir,sizeof(dir),"%s/country",outdir);
  if(mkdir_tree(dir)!=0)goto done;
  snprintf(dir,sizeof(dir),"%s/continent",outdir);
  if(mkdir_tree(dir)!=0)goto done;
  snprintf(dir,sizeof(dir),"%s/ix",outdir);
  if(mkdir_tree(dir)!=0)goto done;

  qsort(m,n,sizeof(IxMetric),cmp_metric_id);
  for(i=0;i<n;i++) {
    snprintf(path,sizeof(path),"%s/ix/%llu.html",outdir,m[i].id);
    if(write_ix_page(path,&m[i])!=0)goto done;
    files++;
  }

  qsort(m,n,sizeof(IxMetric),cmp_metric_asn);
  snprintf(path,sizeof(path),"%s/rank/asn.html",outdir);
  if(write_rank_page(path,"World rank by members (ASNs)","../index.html",m,n,0,NULL,0)!=0)goto done;
  files++;
  for(i=0;i<nc;i++) {
    snprintf(path,sizeof(path),"%s/country/%s.html",outdir,countries[i]);
    snprintf(title,sizeof(title),"Members rank - %.2s",countries[i]);
    if(write_rank_page(path,title,"../index.html",m,n,1,countries[i],0)!=0)goto done;
    files++;
  }
  for(i=0;i<nt;i++) {
    slugify(continents[i],slug,sizeof(slug));
    snprintf(path,sizeof(path),"%s/continent/%s.html",outdir,slug);
    snprintf(title,sizeof(title),"Members rank - %.32s",continents[i]);
    if(write_rank_page(path,title,"../index.html",m,n,2,continents[i],0)!=0)goto done;
    files++;
  }

  qsort(m,n,sizeof(IxMetric),cmp_metric_capacity);
  snprintf(path,sizeof(path),"%s/rank/capacity.html",outdir);
  if(write_rank_page(path,"World rank by total declared port speed","../index.html",m,n,0,NULL,1)!=0)goto done;
  files++;
  qsort(m,n,sizeof(IxMetric),cmp_metric_v4);
  snprintf(path,sizeof(path),"%s/rank/ipv4.html",outdir);
  if(write_rank_page(path,"World rank by IPv4 declared speed","../index.html",m,n,0,NULL,2)!=0)goto done;
  files++;
  qsort(m,n,sizeof(IxMetric),cmp_metric_v6);
  snprintf(path,sizeof(path),"%s/rank/ipv6.html",outdir);
  if(write_rank_page(path,"World rank by IPv6 declared speed","../index.html",m,n,0,NULL,3)!=0)goto done;
  files++;
  qsort(m,n,sizeof(IxMetric),cmp_metric_ports);
  snprintf(path,sizeof(path),"%s/rank/ports.html",outdir);
  if(write_rank_page(path,"World rank by high-speed connections","../index.html",m,n,0,NULL,5)!=0)goto done;
  files++;
  qsort(m,n,sizeof(IxMetric),cmp_metric_facilities);
  snprintf(path,sizeof(path),"%s/rank/facilities.html",outdir);
  if(write_rank_page(path,"World rank by facility footprint","../index.html",m,n,0,NULL,6)!=0)goto done;
  files++;

  snprintf(path,sizeof(path),"%s/index.html",outdir);
  if(write_index(path,countries,nc,continents,nt,m,n)!=0)goto done;
  files++;
  printf("generate: path=%s exchanges=%lu countries=%lu continents=%lu files=%lu\n",outdir,(unsigned long)n,(unsigned long)nc,(unsigned long)nt,files);
  rc=0;
done:
  mysql_close(db);
  free(m);
  return rc;
}

static void usage(const char *argv0) {
  printf("%s %s\n",PROGRAM_NAME,PROGRAM_VERSION);
  printf("usage: %s dbcheck|status|update|generate <path>\n",argv0);
}

int main(int argc,char **argv) {
  int rc;

  rc=1;
  if(curl_global_init(CURL_GLOBAL_DEFAULT)!=0)return 1;
  if(argc==2 && !strcmp(argv[1],"dbcheck"))rc=command_dbcheck();
  else if(argc==2 && !strcmp(argv[1],"status"))rc=command_status();
  else if(argc==2 && !strcmp(argv[1],"update"))rc=command_update();
  else if(argc==3 && !strcmp(argv[1],"generate"))rc=command_generate(argv[2]);
  else {
    usage(argv[0]);
    rc=argc==1 ? 0 : 1;
  }
  curl_global_cleanup();
  return rc;
}
