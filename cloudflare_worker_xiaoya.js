import { connect } from 'cloudflare:sockets';

// 你要反代的小雅服务器地址（后端服务器地址），标准或非标端口均支持
const upstream_url = "http://207.211.189.46:5678";

// 1、需要走CF反代的播放链接地址关键字，走反代的前提是你连接CF的速度不能太慢，可自己想办法优选CF官方或第三方中转IP，太慢卡得难受别来喷我。
// 2、IPv6直播转IPv4反代需要修改my.json/my_ext.json中直播url走小雅反代，例如原url是"https://xhdwc.tk/tvlive.txt"，需要修改为"https://你的小雅worker地址/proxy/https://xhdwc.tk/tvlive.txt"
const proxyList = ["mypikpak", "sharepoint", "http://[", "https://[", "/d/", ".strm"];

// my_fan.json与饭太硬实时同步并插入小雅配置。alitoken_url是自定义的token地址，用于替换玩偶哥哥等需要阿里token的源，客户端就可以不用扫码。留空则不替换，保留饭太硬扫码方式。
// 例如"CF_XIAOYA_ADDRESS/tvbox/token.txt"或"http://xxx.xxx.eu.org:5678/tvbox/token.txt"，你首先要保证该链接指向的阿里token是可以访问的。
const alitoken_url = "CF_XIAOYA_ADDRESS/tvbox/token.txt";

// 下面的配置不懂就尽量不要改了
const replace_dict = {
  '$up_url': '$cust_url'
}

export default {
  async fetch(request, env, ctx) {
    let cust_url = new URL(request.url);
    if (cust_url.pathname.endsWith("my_fan.json")) {
      return fetchFan(request);
    }
    let cust_port = cust_url.port ? `:${cust_url.port}` : "";
    let cust_url_string = `${cust_url.protocol}//${cust_url.hostname}${cust_port}`;
    let _upstream_url = upstream_url;
    let proxy_pathname = "";
    if (cust_url.pathname.startsWith("/proxy/")) {
      let tmpUrl = new URL(cust_url.pathname.split("/proxy/")[1]);
      proxy_pathname = tmpUrl.pathname;
      _upstream_url = `${tmpUrl.protocol}//${tmpUrl.hostname}`;
      if (tmpUrl.port) {
        _upstream_url += ":" + tmpUrl.port;
      }
    }
    let url = new URL(_upstream_url);
    let upstream = _upstream_url.split("://")[1].split(":")[0];
    let original_url_hostname = cust_url.hostname;
    url.search = cust_url.search;
    url.pathname = proxy_pathname ? proxy_pathname : cust_url.pathname;

    let new_request = new Request(url, request);
    let original_response = await fetchOverTcp(new_request);
    let response_headers = original_response.headers;
    let new_response_headers = new Headers(response_headers);

    if (original_response.status === 302 || original_response.status === 301) {
      const locationHeader = new_response_headers.get('location');
      if (locationHeader && isReplace(locationHeader)) {
        let modifiedLocation = locationHeader.replace(/http/g, cust_url_string + "/proxy/" + "http");
        new_response_headers.set('location', modifiedLocation);
      }
    }

    let is_rsp_text = await isTextResponse(original_response);
    if (is_rsp_text) {
      let dic_def = {};
      dic_def["$upstream"] = upstream;
      dic_def["$custom_domain"] = original_url_hostname;
      dic_def["$cust_url"] = cust_url_string;
      dic_def["$up_url"] = `${_upstream_url}`;
      let new_text = replace_response_text(await original_response.text(), dic_def);

      //IPv6反代地址替换
      if (isReplace("https://[") && !new_text.includes("/proxy/")) {
        new_text = new_text.replace(/https:\/\/\[/g, cust_url_string + "/proxy/" + "https://[");
      }
      if (isReplace("http://[") && !new_text.includes("/proxy/")) {
        new_text = new_text.replace(/http:\/\/\[/g, cust_url_string + "/proxy/" + "http://[");
      }

      if (isReplace(new_text)) {
        if (!new_text.includes("/proxy/")) {
          new_text = new_text.replace(/https:/g, cust_url_string + "/proxy/" + "https:");
        }
        if (!new_text.includes("/proxy/")) {
          new_text = new_text.replace(/http:/g, cust_url_string + "/proxy/" + "http:");
        }
      }

      return new Response(new_text, {
        status: original_response.status,
        headers: new_response_headers
      });
    } else {
      return new Response(original_response.body, {
        status: original_response.status,
        headers: new_response_headers
      });
    }
  },
};

async function fetchOverTcp(request) {
  let url = new URL(request.url);
  let req = new Request(url, request);
  let port_string = url.port;
  if (!port_string) {
    port_string = url.protocol === "http:" ? "80" : "443";
  }
  let port = parseInt(port_string);

  if ((url.protocol === "https:" && port === 443) || (url.protocol === "http:" && port === 80)) {
    return await fetch(req);
  }

  // 创建 TCP 连接
  let tcpSocket = connect({
    hostname: url.hostname,
    port: port,
  }, JSON.parse('{"secureTransport": "starttls"}'));

  if (url.protocol === "https:") {
    tcpSocket = tcpSocket.startTls();
  }

  try {
    const writer = tcpSocket.writable.getWriter();

    // 构造请求头部
    let headersString = '';
    let bodyString = '';

    for (let [name, value] of req.headers) {
      if (name === "connection" || name === "host" || name === "x-forwarded-proto" || name === "x-real-ip" || name === "accept-encoding") {
        continue;
      }
      headersString += `${name}: ${value}\r\n`;
    }
    headersString += `connection: close\r\n`;

    let fullpath = url.pathname;

    // 如果有查询参数，将其添加到路径
    if (url.search) {
      fullpath += url.search.replace(/%3F/g, "?");
    }

    const body = await req.text();
    bodyString = `${body}`;

    // 发送请求
    await writer.write(new TextEncoder().encode(`${req.method} ${fullpath} HTTP/1.0\r\nHost: ${url.hostname}:${port}\r\n${headersString}\r\n${bodyString}`));
    writer.releaseLock();

    // 获取响应
    const response = await constructHttpResponse(tcpSocket);

    return response;
  } catch (error) {
    tcpSocket.close();
    return new Response('Internal Server Error', { status: 500 });
  }
}

async function constructHttpResponse(tcpSocket) {
  const reader = tcpSocket.readable.getReader();
  let remainingData = new Uint8Array(0);
  try {
    // 读取响应数据
    while (true) {
      const { value, done } = await reader.read();
      const newData = new Uint8Array(remainingData.length + value.length);
      newData.set(remainingData);
      newData.set(value, remainingData.length);
      remainingData = newData;
      const index = indexOfDoubleCRLF(remainingData);
      if (index !== -1) {
        const headerBytes = remainingData.subarray(0, index);
        const bodyBytes = remainingData.subarray(index + 4);

        const header = new TextDecoder().decode(headerBytes);
        const [statusLine, ...headers] = header.split('\r\n');
        const [httpVersion, statusCode, statusText] = statusLine.split(' ');

        // 构造 Response 对象
        const responseHeaders = JSON.parse("{}");
        headers.forEach((header) => {
          const [name, value] = header.split(': ');
          responseHeaders[name.toLowerCase()] = value;
        });

        const responseInit = {
          status: parseInt(statusCode),
          statusText,
          headers: new Headers(responseHeaders),
        };

        // 使用异步方式逐步读取响应体
        const bodyStream = new ReadableStream({
          async start(controller) {
            controller.enqueue(bodyBytes);
          },
          async pull(controller) {
            while (true) {
              try {
                const { value, done } = await reader.read();
                if (value) {
                  controller.enqueue(value);
                }
                if (done) {
                  controller.close();
                  tcpSocket.close();
                  break;
                }
              } catch (e) {
                controller.close();
                tcpSocket.close();
                return;
              }
            }
          },
        });

        let readable = null;
        let writable = null;
        let stream = null;
        if (responseHeaders["content-length"]) {
          stream = new FixedLengthStream(parseInt(responseHeaders["content-length"]));
        } else {
          stream = new TransformStream();
        }
        readable = stream.readable;
        writable = stream.writable;
        bodyStream.pipeTo(writable);
        return new Response(readable, responseInit);
      }
      if (done) {
        tcpSocket.close();
        break;
      }
    }
    return new Response();
  } catch (error) {
    tcpSocket.close();
    return new Response();
  }
}

function indexOfDoubleCRLF(data) {
  if (data.length < 4) {
    return -1;
  }
  for (let i = 0; i < data.length - 3; i++) {
    if (data[i] === 13 && data[i + 1] === 10 && data[i + 2] === 13 && data[i + 3] === 10) {
      return i;
    }
  }
  return -1;
}

function replace_response_text(text, dic_def) {
  var i, j;
  let new_replace_dict = {};
  for (i in replace_dict) {
    j = replace_dict[i]
    i = dic_def[i] ? dic_def[i] : i;
    j = dic_def[j] ? dic_def[j] : j;
    new_replace_dict[i] = j;
  }

  try {
    for (i in new_replace_dict) {
      j = new_replace_dict[i]
      let re = new RegExp(i, 'g')
      text = text.replace(re, j);
    }
  } catch { }

  return text;
}

function isReplace(urlString) {
  for (let i = 0; i < proxyList.length; i++) {
    if (urlString.includes(proxyList[i])) {
      return true;
    }
  }
  return false;
}

async function readFromStream(stream, size) {
  let bytesRead = 0;
  let chunks = [];
  let reader = null;
  try {
    reader = stream.getReader();
    while (bytesRead < size) {
      const { value, done } = await reader.read();
      if (done) {
        break;
      }
      bytesRead += value.length;
      chunks.push(value);
    }
  } catch (error) {
    //do nothing
  } finally {
    if (reader) {
      reader.releaseLock();
    }
  }

  const resultBuffer = new Uint8Array(bytesRead);
  let offset = 0;
  for (const chunk of chunks) {
    resultBuffer.set(chunk, offset);
    offset += chunk.length;
  }
  stream.cancel();
  return resultBuffer.subarray(0, Math.min(bytesRead, size));
}

async function isTextResponse(original_response) {
  let size = 10000;
  let data = await readFromStream(original_response.clone().body, size);

  // 判断是否为 ASCII 编码
  const isASCII = isASCIIEncoded(data);

  if (isASCII) {
    return true;
  }

  // 判断是否为 UTF-8 编码
  const isUTF8 = isUTF8Encoded(data);

  if (isUTF8) {
    return true;
  }

  // 判断是否为 GBK 编码
  const isGBK = isGBKEncoded(data);

  if (isGBK) {
    return true;
  }

  // 如果都不符合，则不是字符串
  return false;
}

function isASCIIEncoded(data) {
  if (data.length < 1) {
    return false;
  }
  return data.every(byte => byte >= 32 && byte <= 126);
}

function isUTF8Encoded(data) {
  if (data.length < 4) {
    return false;
  }

  for (let i = 0; i < data.length - 4; i++) {
    if (data[i] <= 0x7F) {
      // 单字节编码，符合规则
    } else if (data[i] >= 0xC2 && data[i] <= 0xDF && data[i + 1] >= 0x80 && data[i + 1] <= 0xBF) {
      // 双字节编码，符合规则
      i++;
    } else if (data[i] >= 0xE0 && data[i] <= 0xEF && data[i + 1] >= 0x80 && data[i + 1] <= 0xBF && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF) {
      // 三字节编码，符合规则
      i += 2;
    } else if (data[i] >= 0xF0 && data[i] <= 0xF4 && data[i + 1] >= 0x80 && data[i + 1] <= 0xBF && data[i + 2] >= 0x80 && data[i + 2] <= 0xBF && data[i + 3] >= 0x80 && data[i + 3] <= 0xBF) {
      // 四字节编码，符合规则
      i += 3;
    } else {
      // 其他情况，不符合 UTF-8 编码规则
      return false;
    }
  }

  return true;
}

function isGBKEncoded(data) {
  if (data.length < 2) {
    return false;
  }
  for (let i = 0; i < data.length - 2; i++) {
    if (data[i] >= 0x81 && data[i] <= 0xFE && data[i + 1] >= 0x40 && data[i + 1] <= 0xFE && data[i + 1] != 0x7F) {
      i++;
    } else {
      return false;
    }
  }

  return true;
}

function extract(data) {
  const matcher = data.match(/[A-Za-z0-9]{8}\*\*/);
  return matcher ? data.substring(data.indexOf(matcher[0]) + 10) : "";
}

async function base64Decode(base64String) {
  const binaryString = atob(base64String);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  const text = await new TextDecoder().decode(bytes);
  return text;
}

async function fetchFan(request) {
  try {
    let fan_url = new URL("https://饭太硬.top/tv/");
    let req = new Request(fan_url, request);
    req.headers.set("user-agent", "okhttp/4.11.0");
    let rsp = await fetch(req);
    let cleanText = extract(await rsp.text());
    cleanText = await base64Decode(cleanText);
    cleanText = cleanText.replace(/^\s*\/\/[^\n]*\n/gm, '');
    let cust_url = new URL(request.url);
    let cust_port = cust_url.port ? `:${cust_url.port}` : "";
    let cust_url_string = `${cust_url.protocol}//${cust_url.hostname}${cust_port}`;
    if (alitoken_url) {
      cleanText = cleanText.replace(/http:\/\/127\.0\.0\.1:9978\/file\/tvfan\/token\.txt/g, alitoken_url);
      cleanText = cleanText.replace(/CF_XIAOYA_ADDRESS/g, cust_url_string);
    }
    let fan_json = JSON.parse(cleanText);
    fan_json.sites.unshift({
      "key": "Alist",
      "name": "🌟小雅 | 高清",
      "type": 3,
      "api": cust_url_string + "/tvbox/libs/alist.min.js",
      "searchable": 1,
      "quickSearch": 1,
      "filterable": 0,
      "ext": cust_url_string + "/tvbox/json/alist_ext.json;200;video"
    });
    fan_json.lives.forEach(element => {
      element.url = cust_url_string + "/proxy/" + element.url;
      element.epg = cust_url_string + "/proxy/" + element.epg;
      element.logo = cust_url_string + "/proxy/" + element.logo;
    });
    return new Response(JSON.stringify(fan_json, null, 2));
  } catch (error) {
    return new Response(error, { status: 500 });
  }
}
