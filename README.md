# DLUT_auto_login
## 适用于大连理工大学软件学院的校园网登录python脚本
- 由于本人在纯终端的环境时登录校园网遇到问题，因此写了这个脚本，以方便在终端登录校园网
- 理论上来说，脚本的登录流程是适用校园网的SSO认证，因此在除校园网登录场景外的其他场景也能类似修改后使用
- 所需环境：python3，requirments.txt中的库 ~~(通过chatgpt已将`des.js`转为`des.py`，不再需要nodejs)~~
- 此脚本只在软件学院网络进行过测试，对于其他校区是否可用未进行测试
- 需要注意，在校园网提示密码需要更换时，可能脚本无法正确登录，如下图的场景![alt text](README.assets/image-6.png)
- 最后测试的可使用日期：2024.3.31

## 宇宙级免责声明
- 本脚本只是为了便于非图形化终端的用户登录校园网，没有对校园网有任何攻击行为，也不会泄漏用户个人信息
- 本项目不保证您在当下时间使用时可用，因为校园网的登录方式可能会发生变化
- 本人代码能力低下，分析校园网行为的能力也很弱，如果您对我的代码和校园网行为分析有任何不同意见，欢迎讨论
- 由于本人对python不甚了解，代码大量由chatgpt生成，因此可能存在一些不正确的地方，欢迎指正
- 本项目仅供个人学习交流使用

## 使用方法
- 通过`pip install -r requirements.txt`或手动安装所需库
- 使用示例：`python dlut_autologin.py username password [-i IP]`
- 必须参数为校园网账户和密码，可选参数为当前设备的校园IP地址，因为校园网在未登录时已获取IP，设备可通过`ipconfig/ifconfig/ip addr show`等命令获取，此参数若未给出则通过脚本中的函数自动获取
- ~~dist文件夹下的可执行文件是本人在m2的macmini生成的，也许可以直接使用，并未进行测试~~
- ~~des.js里包含了加密算法，通过chatgpt已将`des.js`转为`des.py`~~

## 校园网行为分析

- 初始访问校园网登录网址"http://172.20.30.2:8080/Self/sso_login?login_method=1&wlan_user_ip={ip}&wlan_user_ipv6=&wlan_user_mac=000000000000&wlan_ac_ip=172.20.30.254&wlan_ac_name=&mac_type=1&authex_enable=&type=1"
- 其中的IP地址为当前设备的校园网IP地址，登录时需要将其替换为当前设备的IP地址，因为校园网在未登录时已获取IP，设备可通过`ipconfig/ifconfig/ip addr show`等命令获取
- 之后会重定向，进行SSO认证（单点登录（英语：Single sign-on，缩写为 SSO），又译为单一签入，一种对于许多相互关连，但是又是各自独立的软件系统，提供访问控制的属性。当拥有这项属性时，当用户登录时，就可以获取所有系统的访问权限，不用对每个单一系统都逐一登录。这项功能通常是以轻型目录访问协议（LDAP）来实现，在服务器上会将用户信息存储到LDAP数据库中。相同的，单一退出（single sign-off）就是指，只需要单一的退出动作，就可以结束对于多个系统的访问权限 [^1]）
- 校园网通过CAS进行SSO认证，下图为CAS流程示意图[^2]
![alt text](README.assets/image.png)
- 成功SSO认证后会重定向进入"http://172.20.30.2:8080/Self/dashboard"页面，并通过"http://172.20.30.2:8080/Self/dashboard/getOnlineList"获取在线设备列表

- 校园网的实际登录流程如下
![alt text](README.assets/image-1.png)
![alt text](README.assets/image-3.png)

  - 登录时post的参数为![alt text](README.assets/image-4.png)
  - 登录的js代码为"https://sso.dlut.edu.cn/cas/comm/js/login6.js?v=20230918"中的`login`函数，如下所示
    ``` javascript
    function login(){
        
        var $u = $("#un") , $p=$("#pd");
        
        var u = $u.val().trim();
        if(u==""){
            $u.focus();
            $("#errormsg").text("账号不能为空。");
            $("#help-link").hide();
            return ;
        }
        
        var p = $p.val().trim();
        if(p==""){
            $p.focus();
            $("#errormsg").text("密码不能为空。");
            $("#help-link").hide();
            return ;
        }
        
        $u.attr("disabled","disabled");
        $p.attr("disabled","disabled");
        
        var lt = $("#lt").val();
        
        $("#ul").val(u.length);
        $("#pl").val(p.length);
        $("#sl").val(0);
        $("#rsa").val(strEnc(u+p+lt , '1' , '2' , '3'));
        
        $("#loginForm")[0].submit();
    }
    ```
    ~~以固定的'1' '2' '3'作为密钥加密不理解😅~~

    其中的加密函数`strEnc`在"https://sso.dlut.edu.cn/cas/comm/js/des.js?v=20211211"

    剩余的一些参数在登录页面被隐藏，如下图所示
    ![alt text](README.assets/image-2.png)

- 通过分析，可以得到登录的大致流程，因此可以用python模拟整个过程，加密函数文件des.js文件已由chatgpt转为des.py，取消了对nodejs的需求(~~其中需要注意的是需要通过额外调用des.js的加密函数进行加密，因此需要将des.js下载到本地，这里通过使用nodejs执行并获取结果，因此本地需要安装nodejs~~)
- 为了更加无脑的使用脚本，而节省手动查询设备IP的过程，脚本中通过遍历所有网络接口获取每个网络接口的IP，由于校园网的IP地址以"172"开头，因此脚本通过此判断是否为校园网IP（这在多网卡设备是否出错并未测试）
- 为了防止在不支持中文的终端中使用会乱码，终端的打印log都是英文

## 运行结果
运行成功后会输出如下结果
![alt text](README.assets/image-5.png)

[^1]: https://zh.wikipedia.org/zh-cn/%E5%96%AE%E4%B8%80%E7%99%BB%E5%85%A5

[^2]: https://apereo.github.io/cas/6.6.x/protocol/CAS-Protocol.html



