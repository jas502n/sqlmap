
## tamper 中文说明

### 作用：

```

apostrophemask.py	作用：用utf8代替引号
apostrophenullencode.py	作用：绕过过滤双引号，替换字符和双引号。
appendnullbyte.py	作用：在有效负荷结束位置加载零字节字符编码
base64encode.py	作用：用base64编码替换 Example: ("1' AND SLEEP(5)#") 'MScgQU5EIFNMRUVQKDUpIw==' Requirement: all
commalesslimit.py
commentbeforeparentheses.py
concat2concatws.py
escapequotes.py
htmlencode.py
informationschemacomment.py
modsecurityzeroversioned.py
securesphere.py	作用：追加特制的字符串
sp_password.py	作用：追加sp_password’从DBMS日志的自动模糊处理的有效载荷的末尾
space2mssqlhash.py	作用：替换空格
symboliclogical.py
unionalltounion.py	作用：替换UNION ALL SELECT UNION SELECT   Example: ('-1 UNION ALL SELECT') '-1 UNION SELECT'
varnish.py
xforwardedfor.py
between.py	作用：用between替换大于号（>） Example: ('1 AND A > B--') '1 AND A NOT BETWEEN 0 AND B--'
bluecoat.py	作用：代替空格字符后与一个有效的随机空白字符的SQL语句。 然后替换=为like
chardoubleencode.py	作用: 双url编码(不处理以编码的)  Example: SELECT FIELD FROM%20TABLE   * Output: %2553%2545%254c%2545%254
charencode.py	作用：url编码   Example:  SELECT FIELD FROM%20TABLE
charunicodeencode.py	作用：字符串 unicode 编码
charunicodeescape.py
commalessmid.py
equaltolike.py	作用：like 代替等号 SELECT * FROM users WHERE id=1   SELECT * FROM users WHERE id LIKE 1
greatest.py	作用：绕过过滤’>’ ,用GREATEST替换大于号。
halfversionedmorekeywords.py	作用：当数据库为mysql时绕过防火墙，每个关键字之前添加mysql版本评论
ifnull2casewhenisnull.py
ifnull2ifisnull.py	作用：绕过对 IFNULL 过滤。 替换类似’IFNULL(A, B)’为’IF(ISNULL(A), B, A)’
least.py
lowercase.py
modsecurityversioned.py	作用：过滤空格，包含完整的查询版本注释   Example: ('1 AND 2>1--') '1 /*!30874AND 2>1*/--'
multiplespaces.py	作用：围绕SQL关键字添加多个空格   Example: ('1 UNION SELECT foobar') '1 UNION SELECT foobar'
nonrecursivereplacement.py	双重查询语句。取代predefined SQL关键字with表示 suitable for替代（例如 .replace（“SELECT”、””)） filters
overlongutf8.py
percentage.py
plus2concat.py
plus2fnconcat.py
randomcase.py	作用：随机大小写 Example: INSERT InsERt
randomcomments.py	作用：用/**/分割sql关键字   Example: ‘INSERT’ becomes ‘IN//S//ERT’
space2comment.py	作用：用'/**/'替换空格   SELECT id FROM users   SELECT//id//FROM/**/users
space2dash.py	作用：绕过过滤‘=’ 替换空格字符（”），（’ – ‘）后跟一个破折号注释，一个随机字符串和一个新行（’ n’）
space2hash.py	作用：空格替换为#号 随机字符串 以及换行符
space2morecomment.py
space2morehash.py	作用：空格替换为 #号 以及更多随机字符串 换行符
space2mssqlblank.py	作用：空格替换为其它空符号mssql
space2mysqlblank.py	作用：空格替换其它空白符号(mysql)  SELECT id FROM users  SELECT%0Bid%0BFROM%A0users
space2mysqldash.py	作用：替换空格字符（”）（’ – ‘）后跟一个破折号注释一个新行（’ n’）
space2plus.py	作用：用+替换空格 Example: ('SELECT id FROM users') 'SELECT+id+FROM+users' Tested against: all
space2randomblank.py	作用：代替空格字符（“ ”）从一个随机的空白字符可选字符的有效集 Example: ('SELECT id FROM users') 'SELECT%0Did%0DFROM%0Ausers'
unmagicquotes.py	作用：宽字符绕过 GPC addslashes Example: 1′ AND 1=1 | 1%bf%27 AND 1=1–%20
uppercase.py
versionedkeywords.py
versionedmorekeywords.py

```
