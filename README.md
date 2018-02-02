# sqlmap
sqlmap

## USE-AGE:

## sqlmap wiki 中文
```
⚡ root@Ubuntu

 sqlmap -hh
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.1.7.21#dev}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

Usage: python sqlmap [options]

Options:
  -h, --help            显示基本帮助信息并退出
  -hh                   显示高级帮助信息并退出
  --version             显示程序的版本号并退出
  -v VERBOSE            详细程度级别：0-6（默认1）

  目标:
    至少必须提供其中一个选项来定义目标

    -d DIRECT           直接数据库连接的连接字符串
    -u URL, --url=URL   目标网址（例如“http://www.site.com/vuln.php?id=1”）
    -l LOGFILE          从Burp或WebScarab代理日志文件解析目标
    -x SITEMAPURL       从远程站点地图（.xml）文件解析目标
    -m BULKFILE         扫描文本文件中给出的多个目标
    -r REQUESTFILE      从文件加载HTTP请求
    -g GOOGLEDORK       将Google dork结果作为目标网址进行处理
    -c CONFIGFILE       从配置INI文件加载选项


  请求:
    这些选项可用于指定如何连接到目标URL

    --method=METHOD     强制使用给定的HTTP方法（例如PUT）
    --data=DATA         要通过POST发送的数据字符串
    --param-del=PARA..  用于分割参数值的字符
    --cookie=COOKIE     HTTP Cookie标头值
    --cookie-del=COO..  用于分割cookie值的字符
    --load-cookies=L..  包含Netscape / wget格式的Cookie的文件
    --drop-set-cookie   忽略来自响应的Set-Cookie头
    --user-agent=AGENT  HTTP用户代理标头值
    --random-agent      使用随机选择的HTTP User-Agent标头值
    --host=HOST         HTTP主机标头值
    --referer=REFERER   HTTP Referer头部值
    -H HEADER, --hea..  额外的头（例如“X-Forwarded-For：127.0.0.1”）
    --headers=HEADERS   额外的标题（例如"Accept-Language: fr\nETag: 123"）
    --auth-type=AUTH..  HTTP认证类型（基本，摘要，NTLM或PKI）
    --auth-cred=AUTH..  HTTP认证凭证（名称：密码）
    --auth-file=AUTH..  HTTP身份验证PEM证书/私钥文件
    --ignore-401        忽略HTTP错误401（未经授权）
    --ignore-proxy      忽略系统默认代理设置
    --ignore-redirects  忽略重定向尝试
    --ignore-timeouts   忽略连接超时
    --proxy=PROXY       使用代理连接到目标网址
    --proxy-cred=PRO..  代理认证凭证（名称：密码）
    --proxy-file=PRO..  从文件加载代理列表
    --tor               使用Tor匿名网络
    --tor-port=TORPORT  设置默认的Tor代理端口
    --tor-type=TORTYPE  设置Tor代理类型（HTTP，SOCKS4或SOCKS5（默认））
    --check-tor         检查Tor是否正确使用
    --delay=DELAY       每个HTTP请求之间的延迟（秒）
    --timeout=TIMEOUT   秒超时连接前等待（默认30）
    --retries=RETRIES   连接超时时重试（默认3）
    --randomize=RPARAM  随机更改给定参数的值
    --safe-url=SAFEURL  测试期间经常访问的URL地址
    --safe-post=SAFE..  POST数据发送到一个安全的URL
    --safe-req=SAFER..  从文件加载安全的HTTP请求
    --safe-freq=SAFE..  两次访问给定的安全URL之间的测试请求
    --skip-urlencode    跳过payload数据的URL编码
    --csrf-token=CSR..  用于保存反CSRF令牌的参数
    --csrf-url=CSRFURL  访问URL地址来提取反CSRF令牌
    --force-ssl         强制使用SSL / HTTPS
    --hpp               使用HTTP参数污染方法
    --eval=EVALCODE     在请求之前评估提供的Python代码（例如：
                         "import hashlib;id2=hashlib.md5(id).hexdigest()")

  Optimization:
    这些选项可以用来优化sqlmap的性能

    -o                  打开所有优化开关
    --predict-output    预测常见的查询输出
    --keep-alive        使用持久HTTP（s）连接
    --null-connection   没有实际的HTTP响应正文检索页面的长度
    --threads=THREADS   并发HTTP请求的最大数量（默认值为1）

  注射:
    这些选项可用于指定要测试的参数，提供自定义注入有效负载和可选的篡改脚本

    -p TESTPARAMETER    可测试的参数（s）
    --skip=SKIP         跳过对给定参数的测试
    --skip-static       跳过似乎不是动态的测试参数
    --param-exclude=..  正则表达式从测试中排除参数（例如“ses”）
    --dbms=DBMS         指定后端DBMS的类型
    --dbms-cred=DBMS..  DBMS身份验证凭据（用户：密码）
    --os=OS             指定后端DBMS操作系统为此值
    --invalid-bignum    使用大数字来使数值无效
    --invalid-logical   使用逻辑操作来使值失效
    --invalid-string    使用随机字符串来使值失效
    --no-cast           关闭payload转换机制
    --no-escape         关闭字符串转义机制
    --prefix=PREFIX     注入payload前缀字符串
    --suffix=SUFFIX     注入payload后缀字符串
    --tamper=TAMPER     使用给定的脚本来篡改注射数据

  发现:
    这些选项可用于自定义检测阶段

    --level=LEVEL       要执行的测试级别（1-5，默认1）
    --risk=RISK         执行测试的风险（1-3，默认1）
    --string=STRING     将查询评估为True时匹配的字符串
    --not-string=NOT..  将查询评估为False时匹配的字符串
    --regexp=REGEXP     当查询评估为True时，正则表达式匹配
    --code=CODE         当查询评估为True时匹配的HTTP代码
    --text-only         仅基于文本内容比较页面
    --titles            仅根据标题比较页面

  技术:
    这些选项可以用来调整特定SQL注入技术的测试

    --technique=TECH    使用SQL注入技术（默认“BEUSTQ”）
    --time-sec=TIMESEC  秒延迟DBMS响应（默认5）
    --union-cols=UCOLS  要测试UNION查询SQL注入的列的范围
    --union-char=UCHAR  用于强化列数的字符
    --union-from=UFROM  在UNION查询SQL注入的FROM部分中使用的表
    --dns-domain=DNS..  用于DNS泄露攻击的域名
    --second-order=S..  生成的页面URL搜索二阶响应

  指纹:
    -f, --fingerprint   执行广泛的DBMS版本指纹

  列举:
    这些选项可用于枚举表中包含的后端数据库管理系统信息，结构和数据。 而且你可以运行你自己的SQL语句

    数据库管理系统 = Database Management System 

    -a, --all           检索一切    
    -b, --banner        获取DBMS banner信息（例如：版本号....）
    --current-user      获取当前用户
    --current-db        获取当前数据库
    --hostname          获取服务器的主机名（root@Jas502n, hostname=Jas502n）
    --is-dba            检测数据库是否是dba权限（取决于是否可以getshell）
    --users             枚举数据库的所有用户名
    --passwords         枚举数据库的用户名与密码
    --privileges        枚举数据库的用户权限（例如：privilege: CREATE、DELETE、UPDATE....）
    --roles             枚举数据库的用户角色（debian-sys-maint'@'localhost=administrator、 mysql.session=SUPER、root'@'% = administrator）
    --dbs               枚举所有数据库名
    --tables            枚举数据库的所有表名
    --columns           枚举数据库表的字段名
    --schema            枚举DBMS模式
    --count             检索表格的条目数（查看数据库数据多少条，例如： -D mysql --count）
    --dump              查看DBMS数据库表项
    --dump-all          查看所有DBMS数据库的表项
    --search            搜索列，表格和/或数据库名称（s）
    --comments          检索DBMS注释
    -D DB               指定一个数据库名
    -T TBL              指定一个数据库表名
    -C COL              DBMS数据库表列要枚举
    -X EXCLUDECOL       DBMS数据库表列不能枚举
    -U USER             DBMS用户列举
    --exclude-sysdbs    枚举表时排除DBMS系统数据库
    --pivot-column=P..  枚举列名称
    --where=DUMPWHERE   查看表时使用where条件语句
    --start=LIMITSTART  选择从多少条开始查看字段内容
    --stop=LIMITSTOP    指定多少条后结束查看字段内容
    --first=FIRSTCHAR   首先查询输出字符来检索
    --last=LASTCHAR     最后一个查询输出字符来检索
    --sql-query=QUERY   要执行的SQL语句
    --sql-shell         进入一个交互式SQL shell
    --sql-file=SQLFILE  从指定的文件里面执行SQL语句

  暴力破解:
    这些选项可以用来暴力检测表名、表字段

    --common-tables     检测默认表名
    --common-columns    检测默认表字段名

  用户自定义函数注入:
    这些选项用户可以用来创建自定义函数

    --udf-inject        用户自定义函数来注入
    --shared-lib=SHLIB  指定本地路径库文件

  访问系统文件:
    这些选项可以访问后端数据库系统的底层文件（例如：/etc/passwd）

    --file-read=RFILE   从后端数据库系统读取系统文件
    --file-write=WFILE  在本地（攻击机）指定一个文件准备写入后端数据库系统上
    --file-dest=DFILE   指定一个绝对路径文件写入后端数据库系统上

  操作系统访问:
    这些选项可用于访问后端数据库系统底层的操作系统

    --os-cmd=OSCMD      执行操作系统命令
    --os-shell          提示使用交互式操作系统shell来getshell
    --os-pwn            获取一个OOB shell，Meterpreter或VNC
    --os-smbrelay       一键提示输入OOB shell，Meterpreter或VNC
    --os-bof            存储过程缓冲区溢出利用
    --priv-esc          数据库进程用户权限升级
    --msf-path=MSFPATH  Metasploit框架的安装位置
    --tmp-path=TMPPATH  远程文件目录的绝对路径

  Windows注册表访问:
    这些选项可用于访问后端数据库管理系统的Windows注册表

    --reg-read          阅读Windows注册表项值
    --reg-add           编写一个Windows注册表键值数据
    --reg-del           删除Windows注册表项值
    --reg-key=REGKEY    Windows注册表项
    --reg-value=REGVAL  Windows注册表项值
    --reg-data=REGDATA  Windows注册表键值数据
    --reg-type=REGTYPE  Windows注册表项值类型

  常见:
    这些选项可以用来设置一些常用的工作参数

    -s SESSIONFILE      从存储的（.sqlite）文件加载会话
    -t TRAFFICFILE      将所有HTTP流量记录到文本文件中
    --batch             永远不要求用户输入，使用默认行为
    --binary-fields=..  具有二进制值的结果字段（例如“digest”）
    --charset=CHARSET   强制用于数据检索的字符编码
    --check-internet    在测试目标之前检查互联网连接
    --crawl=CRAWLDEPTH  从目标网址开始抓取网站
    --crawl-exclude=..  正则表达式排除页面爬行（例如“注销”）
    --csv-del=CSVDEL    分隔CSV输出中使用的字符（默认为“，”）
    --dump-format=DU..  转储数据的格式（CSV（默认），HTML或SQLITE）
    --eta               显示每个输出的预计到达时间
    --flush-session     刷新当前目标的会话文件
    --forms             解析并测试目标网址上的表单
    --fresh-queries     忽略存储在会话文件中的查询结果
    --har=HARFILE       将所有HTTP流量记录到HAR文件中
    --hex               使用DBMS十六进制功能进行数据检索
    --output-dir=OUT..  自定义输出目录路径
    --parse-errors      解析并显示来自响应的DBMS错误消息
    --save=SAVECONFIG   将选项保存到配置INI文件
    --scope=SCOPE       正则表达式从提供的代理日志中筛选目标
    --test-filter=TE..  按照有payload和/或标题选择测试（例如，ROW）
    --test-skip=TEST..  跳过有payload和/或标题的测试（例如，BENCHMARK）
    --update            更新sqlmap


  杂项:
    -z MNEMONICS        使用短助记符（例如"flu,bat,ban,tec=EU"）
    --alert=ALERT       找到SQL注入时运行主机操作系统命令
    --answers=ANSWERS   设置问题答案（例如“quit = N，follow = N”） 
    --beep              在发现问题和/或SQL注入时报警
    --cleanup           从sqlmap特定的UDF和表中清理DBMS
    --dependencies      检查丢失（非核心）的sqlmap依赖项
    --disable-coloring  禁用控制台输出颜色
    --gpage=GOOGLEPAGE  使用google搜索结果中特定的网页数 
    --identify-waf      对WAF / IPS / IDS进行彻底的测试
    --mobile            通过HTTP User-Agent头模拟智能手机
    --offline           在离线模式下工作（仅使用会话数据）
    --purge-output      安全地从输出目录中删除所有内容
    --skip-waf          跳过启发式检测WAF / IPS / IDS保护
    --smart             只有在积极的启发式（s）
    --sqlmap-shell      提示一个交互式的sqlmap shell(极好用)
    --tmp-dir=TMPDIR    用于存储临时文件的本地目录
    --web-root=WEBROOT  Web服务器文档根目录（例如“/var/www”）
    --wizard            简单的向导界面，为初学者用户
 ⚡ root@Ubuntu

```

## sqlmap wiki for en：
```
⚡ root@Ubuntu

 sqlmap -hh
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.1.7.21#dev}
|_ -| . [']     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V          |_|   http://sqlmap.org

Usage: python sqlmap [options]

Options:
  -h, --help            Show basic help message and exit
  -hh                   Show advanced help message and exit
  --version             Show program's version number and exit
  -v VERBOSE            Verbosity level: 0-6 (default 1)

  Target:
    At least one of these options has to be provided to define the
    target(s)

    -d DIRECT           Connection string for direct database connection
    -u URL, --url=URL   Target URL (e.g. "http://www.site.com/vuln.php?id=1")
    -l LOGFILE          Parse target(s) from Burp or WebScarab proxy log file
    -x SITEMAPURL       Parse target(s) from remote sitemap(.xml) file
    -m BULKFILE         Scan multiple targets given in a textual file
    -r REQUESTFILE      Load HTTP request from a file
    -g GOOGLEDORK       Process Google dork results as target URLs
    -c CONFIGFILE       Load options from a configuration INI file

  Request:
    These options can be used to specify how to connect to the target URL

    --method=METHOD     Force usage of given HTTP method (e.g. PUT)
    --data=DATA         Data string to be sent through POST
    --param-del=PARA..  Character used for splitting parameter values
    --cookie=COOKIE     HTTP Cookie header value
    --cookie-del=COO..  Character used for splitting cookie values
    --load-cookies=L..  File containing cookies in Netscape/wget format
    --drop-set-cookie   Ignore Set-Cookie header from response
    --user-agent=AGENT  HTTP User-Agent header value
    --random-agent      Use randomly selected HTTP User-Agent header value
    --host=HOST         HTTP Host header value
    --referer=REFERER   HTTP Referer header value
    -H HEADER, --hea..  Extra header (e.g. "X-Forwarded-For: 127.0.0.1")
    --headers=HEADERS   Extra headers (e.g. "Accept-Language: fr\nETag: 123")
    --auth-type=AUTH..  HTTP authentication type (Basic, Digest, NTLM or PKI)
    --auth-cred=AUTH..  HTTP authentication credentials (name:password)
    --auth-file=AUTH..  HTTP authentication PEM cert/private key file
    --ignore-401        Ignore HTTP Error 401 (Unauthorized)
    --ignore-proxy      Ignore system default proxy settings
    --ignore-redirects  Ignore redirection attempts
    --ignore-timeouts   Ignore connection timeouts
    --proxy=PROXY       Use a proxy to connect to the target URL
    --proxy-cred=PRO..  Proxy authentication credentials (name:password)
    --proxy-file=PRO..  Load proxy list from a file
    --tor               Use Tor anonymity network
    --tor-port=TORPORT  Set Tor proxy port other than default
    --tor-type=TORTYPE  Set Tor proxy type (HTTP, SOCKS4 or SOCKS5 (default))
    --check-tor         Check to see if Tor is used properly
    --delay=DELAY       Delay in seconds between each HTTP request
    --timeout=TIMEOUT   Seconds to wait before timeout connection (default 30)
    --retries=RETRIES   Retries when the connection timeouts (default 3)
    --randomize=RPARAM  Randomly change value for given parameter(s)
    --safe-url=SAFEURL  URL address to visit frequently during testing
    --safe-post=SAFE..  POST data to send to a safe URL
    --safe-req=SAFER..  Load safe HTTP request from a file
    --safe-freq=SAFE..  Test requests between two visits to a given safe URL
    --skip-urlencode    Skip URL encoding of payload data
    --csrf-token=CSR..  Parameter used to hold anti-CSRF token
    --csrf-url=CSRFURL  URL address to visit to extract anti-CSRF token
    --force-ssl         Force usage of SSL/HTTPS
    --hpp               Use HTTP parameter pollution method
    --eval=EVALCODE     Evaluate provided Python code before the request (e.g.
                        "import hashlib;id2=hashlib.md5(id).hexdigest()")

  Optimization:
    These options can be used to optimize the performance of sqlmap

    -o                  Turn on all optimization switches
    --predict-output    Predict common queries output
    --keep-alive        Use persistent HTTP(s) connections
    --null-connection   Retrieve page length without actual HTTP response body
    --threads=THREADS   Max number of concurrent HTTP(s) requests (default 1)

  Injection:
    These options can be used to specify which parameters to test for,
    provide custom injection payloads and optional tampering scripts

    -p TESTPARAMETER    Testable parameter(s)
    --skip=SKIP         Skip testing for given parameter(s)
    --skip-static       Skip testing parameters that not appear to be dynamic
    --param-exclude=..  Regexp to exclude parameters from testing (e.g. "ses")
    --dbms=DBMS         Force back-end DBMS to this value
    --dbms-cred=DBMS..  DBMS authentication credentials (user:password)
    --os=OS             Force back-end DBMS operating system to this value
    --invalid-bignum    Use big numbers for invalidating values
    --invalid-logical   Use logical operations for invalidating values
    --invalid-string    Use random strings for invalidating values
    --no-cast           Turn off payload casting mechanism
    --no-escape         Turn off string escaping mechanism
    --prefix=PREFIX     Injection payload prefix string
    --suffix=SUFFIX     Injection payload suffix string
    --tamper=TAMPER     Use given script(s) for tampering injection data

  Detection:
    These options can be used to customize the detection phase

    --level=LEVEL       Level of tests to perform (1-5, default 1)
    --risk=RISK         Risk of tests to perform (1-3, default 1)
    --string=STRING     String to match when query is evaluated to True
    --not-string=NOT..  String to match when query is evaluated to False
    --regexp=REGEXP     Regexp to match when query is evaluated to True
    --code=CODE         HTTP code to match when query is evaluated to True
    --text-only         Compare pages based only on the textual content
    --titles            Compare pages based only on their titles

  Techniques:
    These options can be used to tweak testing of specific SQL injection
    techniques

    --technique=TECH    SQL injection techniques to use (default "BEUSTQ")
    --time-sec=TIMESEC  Seconds to delay the DBMS response (default 5)
    --union-cols=UCOLS  Range of columns to test for UNION query SQL injection
    --union-char=UCHAR  Character to use for bruteforcing number of columns
    --union-from=UFROM  Table to use in FROM part of UNION query SQL injection
    --dns-domain=DNS..  Domain name used for DNS exfiltration attack
    --second-order=S..  Resulting page URL searched for second-order response

  Fingerprint:
    -f, --fingerprint   Perform an extensive DBMS version fingerprint

  Enumeration:
    These options can be used to enumerate the back-end database
    management system information, structure and data contained in the
    tables. Moreover you can run your own SQL statements

    -a, --all           Retrieve everything
    -b, --banner        Retrieve DBMS banner
    --current-user      Retrieve DBMS current user
    --current-db        Retrieve DBMS current database
    --hostname          Retrieve DBMS server hostname
    --is-dba            Detect if the DBMS current user is DBA
    --users             Enumerate DBMS users
    --passwords         Enumerate DBMS users password hashes
    --privileges        Enumerate DBMS users privileges
    --roles             Enumerate DBMS users roles
    --dbs               Enumerate DBMS databases
    --tables            Enumerate DBMS database tables
    --columns           Enumerate DBMS database table columns
    --schema            Enumerate DBMS schema
    --count             Retrieve number of entries for table(s)
    --dump              Dump DBMS database table entries
    --dump-all          Dump all DBMS databases tables entries
    --search            Search column(s), table(s) and/or database name(s)
    --comments          Retrieve DBMS comments
    -D DB               DBMS database to enumerate
    -T TBL              DBMS database table(s) to enumerate
    -C COL              DBMS database table column(s) to enumerate
    -X EXCLUDECOL       DBMS database table column(s) to not enumerate
    -U USER             DBMS user to enumerate
    --exclude-sysdbs    Exclude DBMS system databases when enumerating tables
    --pivot-column=P..  Pivot column name
    --where=DUMPWHERE   Use WHERE condition while table dumping
    --start=LIMITSTART  First dump table entry to retrieve
    --stop=LIMITSTOP    Last dump table entry to retrieve
    --first=FIRSTCHAR   First query output word character to retrieve
    --last=LASTCHAR     Last query output word character to retrieve
    --sql-query=QUERY   SQL statement to be executed
    --sql-shell         Prompt for an interactive SQL shell
    --sql-file=SQLFILE  Execute SQL statements from given file(s)

  Brute force:
    These options can be used to run brute force checks

    --common-tables     Check existence of common tables
    --common-columns    Check existence of common columns

  User-defined function injection:
    These options can be used to create custom user-defined functions

    --udf-inject        Inject custom user-defined functions
    --shared-lib=SHLIB  Local path of the shared library

  File system access:
    These options can be used to access the back-end database management
    system underlying file system

    --file-read=RFILE   Read a file from the back-end DBMS file system
    --file-write=WFILE  Write a local file on the back-end DBMS file system
    --file-dest=DFILE   Back-end DBMS absolute filepath to write to

  Operating system access:
    These options can be used to access the back-end database management
    system underlying operating system

    --os-cmd=OSCMD      Execute an operating system command
    --os-shell          Prompt for an interactive operating system shell
    --os-pwn            Prompt for an OOB shell, Meterpreter or VNC
    --os-smbrelay       One click prompt for an OOB shell, Meterpreter or VNC
    --os-bof            Stored procedure buffer overflow exploitation
    --priv-esc          Database process user privilege escalation
    --msf-path=MSFPATH  Local path where Metasploit Framework is installed
    --tmp-path=TMPPATH  Remote absolute path of temporary files directory

  Windows registry access:
    These options can be used to access the back-end database management
    system Windows registry

    --reg-read          Read a Windows registry key value
    --reg-add           Write a Windows registry key value data
    --reg-del           Delete a Windows registry key value
    --reg-key=REGKEY    Windows registry key
    --reg-value=REGVAL  Windows registry key value
    --reg-data=REGDATA  Windows registry key value data
    --reg-type=REGTYPE  Windows registry key value type

  General:
    These options can be used to set some general working parameters

    -s SESSIONFILE      Load session from a stored (.sqlite) file
    -t TRAFFICFILE      Log all HTTP traffic into a textual file
    --batch             Never ask for user input, use the default behaviour
    --binary-fields=..  Result fields having binary values (e.g. "digest")
    --charset=CHARSET   Force character encoding used for data retrieval
    --check-internet    Check Internet connection before assessing the target
    --crawl=CRAWLDEPTH  Crawl the website starting from the target URL
    --crawl-exclude=..  Regexp to exclude pages from crawling (e.g. "logout")
    --csv-del=CSVDEL    Delimiting character used in CSV output (default ",")
    --dump-format=DU..  Format of dumped data (CSV (default), HTML or SQLITE)
    --eta               Display for each output the estimated time of arrival
    --flush-session     Flush session files for current target
    --forms             Parse and test forms on target URL
    --fresh-queries     Ignore query results stored in session file
    --har=HARFILE       Log all HTTP traffic into a HAR file
    --hex               Use DBMS hex function(s) for data retrieval
    --output-dir=OUT..  Custom output directory path
    --parse-errors      Parse and display DBMS error messages from responses
    --save=SAVECONFIG   Save options to a configuration INI file
    --scope=SCOPE       Regexp to filter targets from provided proxy log
    --test-filter=TE..  Select tests by payloads and/or titles (e.g. ROW)
    --test-skip=TEST..  Skip tests by payloads and/or titles (e.g. BENCHMARK)
    --update            Update sqlmap

  Miscellaneous:
    -z MNEMONICS        Use short mnemonics (e.g. "flu,bat,ban,tec=EU")
    --alert=ALERT       Run host OS command(s) when SQL injection is found
    --answers=ANSWERS   Set question answers (e.g. "quit=N,follow=N")
    --beep              Beep on question and/or when SQL injection is found
    --cleanup           Clean up the DBMS from sqlmap specific UDF and tables
    --dependencies      Check for missing (non-core) sqlmap dependencies
    --disable-coloring  Disable console output coloring
    --gpage=GOOGLEPAGE  Use Google dork results from specified page number
    --identify-waf      Make a thorough testing for a WAF/IPS/IDS protection
    --mobile            Imitate smartphone through HTTP User-Agent header
    --offline           Work in offline mode (only use session data)
    --purge-output      Safely remove all content from output directory
    --skip-waf          Skip heuristic detection of WAF/IPS/IDS protection
    --smart             Conduct thorough tests only if positive heuristic(s)
    --sqlmap-shell      Prompt for an interactive sqlmap shell
    --tmp-dir=TMPDIR    Local directory for storing temporary files
    --web-root=WEBROOT  Web server document root directory (e.g. "/var/www")
    --wizard            Simple wizard interface for beginner users
 ⚡ root@Ubuntu

```
