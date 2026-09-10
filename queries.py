"""
`queries.py` 负责集中维护所有 Joern DSL 模板。

这里的设计目标是把“查询策略”和“执行流程”拆开：
- `joern_vuln_scanner.py` 负责什么时候查、怎么补上下文
- `queries.py` 负责查什么、不同语言/场景该用哪组 DSL

这样做的好处是：
1. 改 DSL 不需要改调度逻辑
2. 大模型或人工都能更容易理解“当前扫的是什么类型”
3. C/C++ 统一使用 `cpp_queries_merged`（generic 内存/通用类 + embedded 固件类，已合并）
"""

import config  # noqa: F401  # 须在模块级 MAX_PATH_LEN 之前加载 .env

import os
from typing import Dict, List

try:
    # `MAX_PATH_LEN` 控制返回的数据流路径最大深度。
    # 值太小容易漏掉跨函数传播；值太大则会让查询速度和噪声都上升。
    MAX_PATH_LEN = int(os.environ.get("JOERN_MAX_PATH_LEN", "10"))
except Exception:
    MAX_PATH_LEN = 10

# Java 场景下的预定义查询集。
# key 是逻辑漏洞类型名，value 是直接可执行的 Joern DSL。
java_queries = {
    "sql_injection": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(executeQuery|executeUpdate|execute|addBatch|prepareStatement|Statement).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "command_injection": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name(".*(ProcessBuilder|exec|<init>).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "path_traversal": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(File|Path|Files|resolve|write|read|createTempFile).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "xss": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(PrintWriter|Writer.append|println|print|setAttribute|addAttribute|out.print|out.write).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "ssrf": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(URL|HttpURLConnection|HttpClient|RestTemplate|WebClient|openStream|new URI|HttpRequest).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "ldap_injection": f'''
import io.shiftleft.semanticcpg.language._
cpg.call
    .where(
        _.name(".*(DirContext|LdapContext|LdapTemplate|InitialDirContext|search|lookup|bind).*")
        .or(_.code(".*(DirContext|LdapContext|LdapTemplate).*"))
    )
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(10)
    .p
''',
    "xxe": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|XMLReader).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "insecure_deserialization": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(ObjectInputStream|readObject|deserialize|fromXML|fromJson|ObjectMapper).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "weak_crypto": f'''
import io.shiftleft.semanticcpg.language._
cpg.call
    .where(
        _.methodFullName(".*(java\\\\.util\\\\.Random|java\\\\.security\\\\.SecureRandom|MessageDigest\\\\.getInstance|Cipher\\\\.getInstance|KeyGenerator\\\\.getInstance|SecretKeyFactory\\\\.getInstance).*")
        .or(_.code(".*DES|RC2|RC4|MD5|SHA-1|SHA1|ECB|PKCS1.*"))
    )
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "hardcoded_secrets": f'''
import io.shiftleft.semanticcpg.language._
cpg.call
    .where(
        _.name(".*(?i)(setPassword|setSecret|setApiKey|setToken|setKey|setCredential|putExtra|put).*")
        .or(_.code(".*(?i)(password|passwd|secret|api.?key|token|credential|private.?key).*=.*\\"[^\\"]{3,}\\".*"))
    )
    .take(20)
    .code
    .l
''',
    "open_redirect": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(sendRedirect|forward|redirect|setHeader|addHeader|ModelAndView|RedirectView).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "ssti": f'''
import io.shiftleft.semanticcpg.language._
cpg.call
    .where(
        _.methodFullName(".*(Velocity|Freemarker|Thymeleaf|Pebble|Mustache|Jinja|Twig|Template|render|process|evaluate).*")
        .or(_.name(".*(?i)(render|process|evaluate|compile|parse).*"))
    )
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "log_injection": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.methodFullName(".*(Logger|Log|logger|log|slf4j|log4j|logback|java\\\\.util\\\\.logging).*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
    "cors_misconfiguration": f'''
import io.shiftleft.semanticcpg.language._
cpg.call
    .where(
        _.methodFullName(".*(?i)(addAllowedOrigin|setAllowedOrigins|allowedOrigins|CorsConfiguration|CrossOrigin|addCorsMappings).*")
        .or(_.code(".*(?i)(Access-Control-Allow-Origin|allowedOrigins|allowCredentials).*"))
    )
    .take(15)
    .code
    .l
''',
    "file_upload": f'''
import io.shiftleft.semanticcpg.language._
cpg.call
    .where(
        _.methodFullName(".*(MultipartFile|FileUpload|transferTo|getOriginalFilename|save|write|upload|copy).*")
        .or(_.name(".*(transferTo|save|write|upload).*"))
    )
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .take(8)
    .p
''',
}

# Java 反射保守查询（独立 pass，不走 reachableByFlows，避免假路径）
java_reflection_queries = {
    "java_reflection_sites": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.methodFullName("(?i).*(java\\\\.lang\\\\.Class\\\\.forName|java\\\\.lang\\\\.reflect\\\\.Method\\\\.invoke|\\\\.getMethod|\\\\.getDeclaredMethod|\\\\.getConstructor|\\\\.newInstance|ClassLoader\\\\.loadClass).*")
  )
  .take(120)
  .code
  .l
""",
    "java_reflection_forname_literals": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .name("forName")
  .where(_.argument(1).isLiteral)
  .take(80)
  .code
  .l
""",
    "java_reflection_invoke_sites": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .name("invoke")
  .where(_.methodFullName("(?i).*java\\\\.lang\\\\.reflect\\\\.Method.*"))
  .take(80)
  .code
  .l
""",
}

# ---------------------------------------------------------------------------
# 逻辑漏洞专用查询集（Java / Spring Boot）
# 不依赖 reachableByFlows，而是枚举端点/守卫/敏感操作做交叉分析
# ---------------------------------------------------------------------------
java_logic_queries = {
    # 端点枚举：找出所有 Controller 路由方法（含注解元数据）
    "endpoint_enumeration": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|Path|WebEndpoint)"))
  .map(m => s"${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(200)
  .l
""",
    # 端点参数提取：找出 Controller 方法的 @RequestParam/@PathVariable/@RequestBody 参数
    "endpoint_parameters": """
import io.shiftleft.semanticcpg.language._
val endpointMethods = cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .take(200)
  .l
endpointMethods.flatMap { m =>
  m.parameter.filterNot(_.name == "this").map { p =>
    val annNames = p.annotation.name.l
    val relevantAnns = annNames.filter(a =>
      a.matches("(?i)(RequestParam|PathVariable|RequestBody|ModelAttribute|RequestHeader|CookieValue|MatrixVariable)")
    )
    if (relevantAnns.nonEmpty) {
      s"ENDPOINT_PARAM | method=${m.fullName} | name=${p.name} | type=${p.typeFullName} | annotations=${relevantAnns.mkString(",")}"
    } else if (annNames.isEmpty) {
      s"ENDPOINT_PARAM | method=${m.fullName} | name=${p.name} | type=${p.typeFullName} | annotations=implicit"
    } else {
      null
    }
  }.filter(_ != null)
}
""",
    # 入口 callee 追溯：从 Controller 方法向下 2 层，记录调用了哪些方法
    # 使用 m.call.l 直接 AST 遍历（与 sensitive_operations 等已验证查询同模式）
    "entry_callees": """
import io.shiftleft.semanticcpg.language._
val _noise = Set("toString","hashCode","equals","getClass","notify","wait","clone")
val entryMethods = cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .take(200)
  .l
val l1Data = entryMethods.flatMap { m =>
  m.call.l.filter(c =>
    c.name.length > 2 && !_noise.contains(c.name) &&
    !c.methodFullName.startsWith("<")
  ).map(c => (m.fullName, c.methodFullName, c.name))
}
val l1Results = l1Data.map { case (entry, callee, cn) =>
  s"ENTRY_CALLEE | entry=${entry} | callee=${callee} | depth=1 | calleeName=${cn}"
}
val l1CalleeFns = l1Data.map(_._2).distinct
val l2Data = l1CalleeFns.flatMap { fn =>
  val entryOpt = l1Data.find(_._2 == fn).map(_._1)
  entryOpt match {
    case Some(entryFn) =>
      cpg.method.fullNameExact(fn).call.l
        .filter(c => c.name.length > 2 && !_noise.contains(c.name) && !c.methodFullName.startsWith("<"))
        .map(c => (entryFn, c.methodFullName, c.name))
    case None => List.empty
  }
}
val l2Results = l2Data.map { case (entry, callee, cn) =>
  s"ENTRY_CALLEE | entry=${entry} | callee=${callee} | depth=2 | calleeName=${cn}"
}
(l1Results ++ l2Results).distinct.take(50)
""",
    # 鉴权守卫检测：注解级 + 代码级
    "auth_guards": """
import io.shiftleft.semanticcpg.language._
val annotGuards = cpg.method
  .where(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresAuthentication|RequiresRoles|AuthenticationPrincipal|LoginRequired|AuthRequired|DenyAll|PermitAll|EnableGlobalMethodSecurity)"))
  .map(m => s"ANNOTATION_GUARD | ${m.fullName} | ${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
val codeGuards = cpg.call
  .where(_.name("(?i)(isAuthenticated|hasRole|hasPermission|checkPermission|authorize|requireAuth|isAdmin|isAuthorized|getAuthentication|getCurrentUser|getPrincipal|getCurrentUserId|checkAccess|getSecurityContext)"))
  .map(c => s"CODE_GUARD | ${c.methodFullName} | caller=${c.method.fullName} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
val paramIdentityGuards = cpg.method
  .where(_.parameter.annotation.name("(?i)(CurrentUser|CurrentUsername|AuthenticationPrincipal|Principal|LoggedInUser|ActiveUser)"))
  .map(m => s"PARAM_IDENTITY_GUARD | ${m.fullName} | params=${m.parameter.name.l.mkString(",")}")
  .take(120)
  .l
val jaxrsGuards = cpg.method
  .where(_.annotation.name("(?i)(RolesAllowed|PermitAll|DenyAll)"))
  .map(m => s"JAXRS_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
(annotGuards ++ codeGuards ++ paramIdentityGuards ++ jaxrsGuards).distinct
""",
    # ── 类级鉴权注解：@PreAuthorize 等放在 class 上，保护所有方法 ──
    "class_level_auth": """
import io.shiftleft.semanticcpg.language._
cpg.typeDecl
  .where(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresAuthentication|RequiresRoles|DenyAll)"))
  .map(t => s"CLASS_AUTH | ${t.fullName} | annotations=${t.annotation.name.l.mkString(",")} | file=${t.file.name.headOption.getOrElse("?")}")
  .take(100)
  .l
""",
    # ── AOP 切面鉴权：@Aspect 中 @Around/@Before 拦截权限相关逻辑 ──
    "aop_auth_aspects": """
import io.shiftleft.semanticcpg.language._
cpg.typeDecl
  .where(_.annotation.name("(?i)(Aspect)"))
  .method
  .where(_.annotation.name("(?i)(Around|Before|After|Pointcut)"))
  .where(_.code("(?i).*(auth|perm|permission|role|access|privilege|scope|DataScope|RequirePerm|RequiresAuth|CheckLogin|isAuthenticated|hasRole|checkAccess)"))
  .map(m => s"AOP_AUTH | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | pointcut=${m.annotation.code.l.mkString(";")} | code_preview=${m.code.take(400)}")
  .take(30)
  .l
""",
    # ── 自定义鉴权注解：端点方法上非标准但含 auth 关键词的注解（可能由 AOP 拦截器支撑） ──
    "custom_auth_annotations": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .filter(_.annotation.name.l.exists(a => a.matches("(?i).*(auth|perm|role|access|login|scope|privilege|require|check|guard|DataScope).*") && !Set("PreAuthorize","Secured","RolesAllowed","RequiresPermissions","RequiresAuthentication","RequiresRoles","Authenticated","DenyAll","PermitAll").contains(a)))
  .map(m => {
    val customAnnots = m.annotation.name.l.filter(a => a.matches("(?i).*(auth|perm|role|access|login|scope|privilege|require|check|guard|DataScope).*") && !Set("PreAuthorize","Secured","RolesAllowed","RequiresPermissions","RequiresAuthentication","RequiresRoles","Authenticated","DenyAll","PermitAll").contains(a))
    s"CUSTOM_AUTH_ANNOTATION | names=${customAnnots.mkString(",")} | method=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")}"
  })
  .take(80)
  .l
""",
    # ── 框架安全默认值检测：@EnableWebSecurity / 无自定义 FilterChain 时的默认保护行为 ──
    "framework_security_defaults": """
import io.shiftleft.semanticcpg.language._
val enableWebSec = cpg.typeDecl
  .where(_.annotation.name("(?i)(EnableWebSecurity|EnableWebFluxSecurity|EnableMethodSecurity|EnableGlobalMethodSecurity)"))
  .map(t => s"ENABLE_SECURITY | ${t.fullName} | annotations=${t.annotation.name.l.mkString(",")} | file=${t.file.name.headOption.getOrElse("?")}")
  .take(10).l
val hasFilterChain = cpg.method
  .name("(?i)^(securityFilterChain|filterChain)$")
  .map(m => s"HAS_FILTER_CHAIN | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")}")
  .take(5).l
val noFilterChain = if (hasFilterChain.isEmpty) List("NO_CUSTOM_FILTER_CHAIN | Spring Security default: all endpoints require authentication unless explicitly permitAll") else List()
(enableWebSec ++ hasFilterChain ++ noFilterChain)
""",
    # 敏感操作枚举：DB/文件/管理员/支付/消息/外部调用操作
    # Joern 4.x: 嵌套 .or() 在 .where() 内可能失效，改用分离查询 + 合并
    "sensitive_operations": """
import io.shiftleft.semanticcpg.language._
val byName = cpg.call
  .name("(?i)^(save|saveAll|saveAndFlush|delete|deleteAll|update|remove|insert|execute|executeUpdate|executeQuery|transfer|withdraw|deposit|send|sendMail|sendEmail|publish|upload|download|create|createUser|deleteUser|resetPassword|grantRole|revokeRole)$")
  .l
val byMethod = cpg.call
  .methodFullName("(?i).*(Repository|RestTemplate|WebClient|FeignClient|JdbcTemplate|EntityManager).*")
  .l
val byCode = cpg.call
  .code("(?i).*(\\\\.save|\\\\.delete|\\\\.update|\\\\.remove|\\\\.insert|\\\\.execute|\\\\.transfer|\\\\.upload|\\\\.download|\\\\.send).*\\\\(")
  .whereNot(_.name("(?i)^(toString|hashCode|equals|getClass|notify|wait)$"))
  .l
(byName ++ byMethod ++ byCode).distinct
  .map(c => {
    val cc1 = c.method.caller.headOption
    val cc2 = cc1.flatMap(_.caller.headOption)
    val cc = List(cc1, cc2).flatten.map(_.fullName).mkString(";")
    s"SENSITIVE_OP | ${c.name} | method=${c.methodFullName} | caller=${c.method.fullName} | caller_chain=${cc} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}"
  })
  .take(150)
  .l
""",
    # IDOR 候选：方法参数直接用于 DB/文件查询（无 owner 绑定）
    # Joern 4.x: 分离查询 + 合并，避免嵌套 .or() 失效
    "idor_candidates": """
import io.shiftleft.semanticcpg.language._
val byName = cpg.call
  .name("(?i)^(findById|getById|findOne|deleteById|updateById|getOne|getReferenceById|findBySlug|findByCode|findByName|findAllById|getProfile|getUser|findUser|getEmployee)$")
  .l
val byCode = cpg.call
  .code("(?i).*(findById|getById|findOne|deleteById|findBySlug|findByCode|findByName|getProfile|getUser)\\\\(")
  .l
val byMethod = cpg.call
  .methodFullName("(?i).*(Repository|Dao|Store|Manager).*(get|find|load|fetch|retrieve|query)\\\\w*")
  .l
(byName ++ byCode ++ byMethod).distinct
  .map(c => {
    val params = c.argument.isIdentifier.name.l
    s"IDOR_CANDIDATE | ${c.name}(${params.mkString(",")}) | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}"
  })
  .take(80)
  .l
""",
    # ── IDOR 深度：PathVariable/RequestParam 直接作为资源标识符 ──
    "idor_path_variable": """
import io.shiftleft.semanticcpg.language._
val pathVarMethods = cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .filter(_.parameter.exists(p => p.annotation.name("(?i)PathVariable").nonEmpty))
  .whereNot(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|CurrentUsername|CurrentUser)"))
  .filterNot(_.parameter.exists(p => p.annotation.name("(?i)(CurrentUser|CurrentUsername|AuthenticationPrincipal|Principal)").nonEmpty))
  .map(m => s"IDOR_PATHVAR | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(80)
  .l
val reqParamWriteMethods = cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|DeleteMapping|PatchMapping)"))
  .filter(_.parameter.exists(p => p.annotation.name("(?i)RequestParam").nonEmpty))
  .whereNot(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed)"))
  .filterNot(_.parameter.exists(p => p.annotation.name("(?i)(CurrentUser|CurrentUsername|AuthenticationPrincipal|Principal)").nonEmpty))
  .map(m => s"IDOR_REQPARAM | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(80)
  .l
(pathVarMethods ++ reqParamWriteMethods).distinct
""",
    # ── IDOR/Profile：用户标识符来自路径/参数但未与当前主体比对 ──
    "idor_profile": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .where(_.code("(?i).*(findByUsername|findByUserName|findByEmail|getProfile|updateProfile|userProfile|UserProfile|getUser|loadUser|userRepository|profileRepository|UserRepository).*"))
  .whereNot(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions)"))
  .filterNot(_.parameter.exists(p => p.annotation.name("(?i)(CurrentUser|CurrentUsername|AuthenticationPrincipal|Principal)").nonEmpty))
  .filterNot(_.call.code("(?i).*(getCurrentUser|getAuthentication|SecurityContextHolder|principal[.]getName|Objects[.]equals.*user).*").l.nonEmpty)
  .map(m => s"IDOR_PROFILE | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(80)
  .l
""",
    # ── 越权操作：管理级操作无角色校验 ──
    "admin_ops_no_auth": """
import io.shiftleft.semanticcpg.language._
val adminOps = cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.methodFullName("(?i).*(findAll|findAllUsers|listUsers|getAllUsers|save|addUser|deleteUser|removeUser|createUser|updateRole|grantRole|revokeRole|setAdmin|makeAdmin).*").l.nonEmpty)
  .whereNot(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresAuthentication|RequiresRoles|DenyAll)"))
  .map(m => s"ADMIN_OP_NO_AUTH | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.methodFullName.l.filter(_.matches("(?i).*(findAll|save|delete|add|remove|update|grant|revoke|setAdmin|makeAdmin).*")).take(3).mkString(";")}")
  .take(50)
  .l
adminOps
""",
    # ── JWT 弱点：弱密钥/弱随机/禁用验证 ──
    "jwt_weakness": """
import io.shiftleft.semanticcpg.language._
val jwtMethods = cpg.method
  .filter(_.call.methodFullName("(?i).*(Jwts|Jwt|JWT|jsonwebtoken|JwtBuilder|JwtParser).*").l.nonEmpty)
  .l
val weakSecrets = jwtMethods
  .filter(_.call.code("(?i).*(new Random\\\\(|Math\\\\.random|SECRETS|SECRET_KEY|jwt\\\\.secret|signingKey|setSigningKey).*").l.nonEmpty)
  .map(m => s"JWT_WEAK_SECRET | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(30)
  .l
val noVerify = jwtMethods
  .filter(_.call.code("(?i).*(setAllowedClockSkew|disableVerification|parseClaimsJwsWithout|unsafeAccept|acceptExpired|WITHOUT_SIGNATURE_VERIFICATION).*").l.nonEmpty)
  .map(m => s"JWT_NO_VERIFY | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(20)
  .l
val algConfusion = jwtMethods
  .filter(_.call.code("(?i).*(none|alg.*none|Algorithm\\\\.none|HS256.*RS256|setAlgorithm).*").l.nonEmpty)
  .map(m => s"JWT_ALG_CONFUSION | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(20)
  .l
(weakSecrets ++ noVerify ++ algConfusion).distinct
""",
    # ── JWT 端点：HTTP 接口直接签发/解析/刷新 token（独立于 missing_auth 交叉）──
    "jwt_endpoints": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.methodFullName("(?i).*(Jwts|JwtBuilder|JwtParser|signWith|parseClaimsJws|parseClaimsJwt|setSigningKey|verifyWith|decodeJwt|refreshToken|newToken).*").l.nonEmpty)
  .map(m => s"JWT_ENDPOINT | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.methodFullName.l.filter(_.matches("(?i).*(Jwt|sign|parse|verify|token).*")).take(4).mkString(";")}")
  .take(50)
  .l
""",
    # ── 文件操作风险：端点中用户可控的文件路径 ──
    "file_ops_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.methodFullName("(?i).*(FileInputStream|FileOutputStream|File[.]copy|Files[.]|FileCopyUtils|Paths[.]get|Path[.]resolve|getResourceAsStream|new File).*").l.nonEmpty)
  .map(m => s"FILE_OPS_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.methodFullName.l.filter(_.matches("(?i).*(File|Path|Copy).*")).take(3).mkString(";")}")
  .take(50)
  .l
""",
    # ── 批量数据暴露：端点返回含敏感字段的全量列表 ──
    "mass_data_exposure": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|RequestMapping)"))
  .filter(_.call.code("(?i).*(findAll|getAll|selectAll|listAll|findAllUsers|getAllUsers|getEmployees).*").l.nonEmpty)
  .filter(_.call.code("(?i).*(salary|ssn|password|secret|creditCard|email|phone|accountNumber|token|apiKey|privateKey).*").l.nonEmpty)
  .whereNot(_.call.code("(?i).*(isAdmin|hasRole|checkPermission|authorize|@CurrentUsername|getCurrentUser|getAuthentication).*"))
  .map(m => s"MASS_DATA_EXPOSURE | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    # 信息泄露候选：异常处理/日志/响应中泄露敏感数据
    "info_leak_candidates": """
import io.shiftleft.semanticcpg.language._
val exceptionHandlers = cpg.method
  .annotation.name("(?i)(ExceptionHandler|ControllerAdvice)")
  .l
val exceptionLeaks = cpg.method
  .name("(?i)(handleException|exceptionHandler|handleError|onError|handle)")
  .filter(m => exceptionHandlers.exists(eh => eh.fullName == m.fullName))
  .map(m => s"EXCEPTION_LEAK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")}")
  .take(30)
  .l
val sensitiveLogs = cpg.call
  .name("(?i)(error|warn|info|debug|log)")
  .filter(_.argument.code("(?i).*(password|secret|token|ssn|creditCard|privateKey|apiKey|email|accountNumber).*").l.nonEmpty)
  .map(c => s"SENSITIVE_LOG | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | arg=${c.argument.code.l.mkString(",").take(80)} | line=${c.lineNumber.getOrElse(0)}")
  .take(50)
  .l
(exceptionLeaks ++ sensitiveLogs).distinct
""",
    # 响应体信息泄露：异常/堆栈/内部错误直接返回客户端
    "info_leak_response": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|ExceptionHandler|ControllerAdvice)"))
  .filter(_.call.code("(?i).*(getMessage|printStackTrace|toString|ResponseEntity.*body|ResponseEntity.*exception|stackTrace|writeValueAsString).*").l.nonEmpty)
  .map(m => s"RESPONSE_LEAK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(60)
  .l
""",
    # CSRF 缺口：状态变更端点无 token 校验或全局禁用 CSRF
    "csrf_gap": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|DeleteMapping|PatchMapping)"))
  .whereNot(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed)"))
  .filterNot(_.call.code("(?i).*(CsrfToken|csrfToken|_csrf|X-CSRF|XSRF).*").l.nonEmpty)
  .map(m => s"CSRF_GAP | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(80)
  .l
""",
    # SSRF 业务上下文：HTTP 端点发起出站请求（逻辑层评估 URL 校验，非仅污点流）
    "ssrf_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.methodFullName("(?i).*(RestTemplate|WebClient|HttpClient|HttpURLConnection|URLConnection|openStream|getForObject|postForObject|exchange|HttpRequest|OkHttp|URI[.]create|new URL).*").l.nonEmpty)
  .map(m => s"SSRF_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.methodFullName.l.filter(_.matches("(?i).*(RestTemplate|WebClient|Http|URI|URL|openStream).*")).take(4).mkString(";")}")
  .take(60)
  .l
""",
    # 业务逻辑错误：客户端可控 price/qty/status/role 等被直接信任
    "business_logic_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .where(_.code("(?i).*(price|amount|quantity|total|discount|balance|status|role|isadmin|coupon|credit|step).*"))
  .filter(_.call.code("(?i).*(setPrice|setAmount|setTotal|setQuantity|setStatus|setRole|setDiscount|grantRole|setBalance|setCredit|setStep).*").l.nonEmpty)
  .map(m => s"BIZLOGIC_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(80)
  .l
""",
    # CWE-841: 多步工作流/支付/审批 — 敏感终态操作缺少步骤校验
    "workflow_bypass": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .where(_.code("(?i).*(checkout|confirm|submit|approve|complete|finalize|placeOrder|processPayment|workflow|orderStatus|step).*"))
  .filterNot(_.call.code("(?i).*(validateStep|checkPreviousStep|isStepComplete|requireStep|assertState|canTransition|verifyStep).*").l.nonEmpty)
  .map(m => s"WORKFLOW_BYPASS | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(60)
  .l
""",
    # CWE-863: 授权判断依赖 Cookie/Header/参数等不可信来源
    "incorrect_authz_source": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|PatchMapping|RequestMapping|Controller)"))
  .where(_.code("(?i).*(role|permission|isAdmin|userType|user_type|authorized|privilege).*"))
  .where(_.code("(?i).*(getParameter|getHeader|getCookie|@CookieValue|@RequestHeader|request[.]get).*"))
  .map(m => s"UNTRUSTED_AUTHZ | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(60)
  .l
""",
    # CWE-836: 认证入口直接比对客户端预哈希密码
    "client_hash_auth": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(
    _.name("(?i)(login|authenticate|signin|verify|auth|doLogin)")
    .or(_.annotation.name("(?i)(PostMapping|RequestMapping)"))
  )
  .where(_.code("(?i).*(hash|digest|md5|sha256|sha1|MessageDigest|passwordHash|clientHash|preHash).*"))
  .map(m => s"CLIENT_HASH_AUTH | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    # CWE-287: 登录/认证端点缺少标准认证栈或弱比对
    "auth_weakness": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|RequestMapping|GetMapping)"))
  .where(_.name("(?i)(login|authenticate|signin|auth|doLogin|attemptAuthentication).*"))
  .filterNot(_.call.methodFullName("(?i).*(AuthenticationManager|UserDetailsService|PasswordEncoder|DaoAuthenticationProvider).*").l.nonEmpty)
  .map(m => s"AUTH_WEAKNESS | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    # CWE-285: 资源访问缺少 owner/tenant 绑定（业务层水平越权）
    "business_authz_gap": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.code("(?i).*(findById|getById|findOne|deleteById|getReferenceById).*").l.nonEmpty)
  .whereNot(_.code("(?i).*(owner|tenant|patient|userId|user_id|currentUser|getAuthentication|SecurityContext|principal).*"))
  .map(m => s"BIZ_AUTHZ_GAP | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(60)
  .l
""",
    # CWE-79: 用户输入进入 HTML/模板输出（逻辑层：是否编码/是否 utext）
    "xss_output_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|ResponseBody|Controller)"))
  .filter(_.call.code("(?i).*(model[.]addAttribute|addObject|writer[.]print|writer[.]write|ResponseEntity[.]ok|th:utext|innerHTML).*").l.nonEmpty)
  .filter(_.parameter.l.nonEmpty)
  .map(m => s"XSS_OUTPUT_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    # TOCTOU：先检查文件/资源状态再操作，无原子性或锁
    "toctou_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .filter(_.call.code("(?i).*(exists|canRead|isFile|Files[.]exists|fileExists).*").l.nonEmpty)
  .filter(_.call.code("(?i).*(delete|write|create|move|copy|rename|upload|download|transfer).*").l.nonEmpty)
  .map(m => s"TOCTOU_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # CORS 配置审计
    "cors_config": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(addAllowedOrigin|setAllowedOrigins|allowedOrigins|addMapping|addCorsMappings|setAllowedHeaders|allowCredentials)")
    .or(_.code("(?i)(Access-Control-Allow-Origin|CorsConfiguration|CorsFilter|CrossOrigin)"))
  )
  .map(c => s"CORS_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # 硬编码凭证 v2（增强版）
    # Joern 4.x / Scala: 正则中 $ 需用 \\\\$ 转义，{ 不需转义
    "hardcoded_credentials_v2": """
import io.shiftleft.semanticcpg.language._
cpg.literal
  .where(_.inAssignment.target.code("(?i).*(password|passwd|pwd|secret|apiKey|api_key|token|credential|privateKey|private_key|authKey|accessKey|secretKey|connectionString|awsKey|clientSecret|jwtSecret).*"))
  .filter(_.code.length > 4)
  .whereNot(_.code("(?i)(null|empty|none|TODO|CHANGE_ME|xxx|placeholder)"))
  .map(lit => s"HARDCODED_CRED | value=${lit.code.take(60)} | method=${lit.inCall.method.fullName.l.headOption.getOrElse("?")} | file=${lit.file.name.headOption.getOrElse("?")} | line=${lit.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    # Spring Security 过滤器链（5.x–6.x 通用；按 API/方法名模式，不写死项目或类名）
    "security_filter_chain": """
import io.shiftleft.semanticcpg.language._
val filterChainBeans = cpg.method
  .name("(?i)^(securityFilterChain|filterChain)$")
  .l
val legacyConfigurer = cpg.method
  .name("(?i)^configure$")
  .where(_.code("(?i).*(HttpSecurity|WebSecurityConfigurerAdapter|authorizeRequests|antMatchers|mvcMatchers)"))
  .l
val securityConfigBodies = cpg.method
  .where(_.code("(?i).*(authorizeHttpRequests|authorizeRequests|requestMatchers|antMatchers|mvcMatchers|regexMatchers|permitAll|authenticated|http[.]authorize|SecurityFilterChain|WebSecurityConfigurerAdapter)"))
  .l
(filterChainBeans ++ legacyConfigurer ++ securityConfigBodies).distinct
  .map(m => {
    val fn = m.file.name.headOption.getOrElse("unknown")
    val raw = m.code.take(2000)
    s"SECURITY_CONFIG | ${m.fullName} | file=${fn}" + "\\n" + raw
  })
  .take(20)
  .l
""",
    # Apache Shiro：注解守卫 + SecurityUtils/Subject 代码守卫
    "shiro_auth_guards": """
import io.shiftleft.semanticcpg.language._
val shiroAnnot = cpg.method
  .where(_.annotation.name("(?i)(RequiresAuthentication|RequiresPermissions|RequiresRoles|RequiresUser|RequiresGuest)"))
  .map(m => s"SHIRO_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(80)
  .l
val shiroCode = cpg.call
  .where(_.methodFullName("(?i).*(SecurityUtils[.]getSubject|Subject[.]isAuthenticated|Subject[.]isPermitted|Subject[.]hasRole|subject[.]isPermitted|subject[.]hasRole)"))
  .map(c => s"SHIRO_CODE_GUARD | caller=${c.method.fullName} | line=${c.lineNumber.getOrElse(0)}")
  .take(80)
  .l
(shiroAnnot ++ shiroCode).distinct
""",
    # Apache Shiro：filterChainDefinitions / SecurityManager 配置
    "shiro_security_config": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.code("(?i).*(ShiroFilterFactoryBean|DefaultWebSecurityManager|IniSecurityManagerFactory|filterChainDefinitions|filterChainDefinitionMap|shiro[.]ini|SecurityUtils[.]setSecurityManager)"))
  .map(m => s"SHIRO_CONFIG | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | code_preview=${m.code.take(200)}")
  .take(30)
  .l
""",
    # JAX-RS / Jakarta REST：声明式角色注解
    "jaxrs_auth_guards": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(RolesAllowed|PermitAll|DenyAll)"))
  .map(m => s"JAXRS_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
""",
    # JAX-RS 资源：@Path 等入口但无 JAX-RS/Spring 声明式鉴权
    "jaxrs_unprotected_resources": """
import io.shiftleft.semanticcpg.language._
val jaxrsEndpoints = cpg.method
  .where(_.annotation.name("(?i)(Path|GET|POST|PUT|DELETE|PATCH|HttpMethod)"))
  .l
val jaxrsGuarded = cpg.method
  .where(_.annotation.name("(?i)(RolesAllowed|PermitAll|DenyAll)"))
  .fullName.toSet
val springGuarded = cpg.method
  .where(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresAuthentication)"))
  .fullName.toSet
jaxrsEndpoints
  .filter(m => !jaxrsGuarded.contains(m.fullName) && !springGuarded.contains(m.fullName))
  .map(m => s"JAXRS_UNPROTECTED | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(80)
  .l
""",
    # 无鉴权端点：找出 permitAll / 无任何安全注解的公开端点
    # Joern 4.x: .filter + .nonEmpty / .isEmpty 替代 .where(!_)  
    "public_endpoints": """
import io.shiftleft.semanticcpg.language._
val allEndpoints = cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|Path|WebEndpoint)"))
  .l
val securedNames = cpg.method
  .where(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresAuthentication|RequiresRoles|Authenticated|DenyAll)"))
  .fullName.toSet
val classSecuredTypes = cpg.typeDecl
  .where(_.annotation.name("(?i)(PreAuthorize|Secured|RolesAllowed|RequiresPermissions|RequiresAuthentication|RequiresRoles|DenyAll)"))
  .fullName.toSet
val classSecuredMethods = cpg.method
  .filter(m => classSecuredTypes.contains(m.typeDecl.fullName.headOption.getOrElse("")))
  .fullName.toSet
val identityBoundNames = cpg.method
  .where(_.parameter.annotation.name("(?i)(CurrentUser|CurrentUsername|AuthenticationPrincipal|Principal|LoggedInUser|ActiveUser)"))
  .fullName.toSet
allEndpoints
  .filterNot(m => securedNames.contains(m.fullName))
  .filterNot(m => classSecuredMethods.contains(m.fullName))
  .filterNot(m => identityBoundNames.contains(m.fullName))
  .map(m => s"PUBLIC_ENDPOINT | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
""",
    # ── SQL 注入风险：端点中使用字符串拼接构造 SQL ──
    "sqli_risk": """
import io.shiftleft.semanticcpg.language._
val sqlCallers = cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.methodFullName("(?i).*(executeQuery|executeUpdate|execute|prepareStatement|createQuery|createNativeQuery|jdbcTemplate).*").l.nonEmpty)
  .l
val withConcat = sqlCallers
  .filter(_.call.code("(?i).*(SELECT|INSERT|UPDATE|DELETE).*([+]|concat|format).*").l.nonEmpty)
  .map(m => s"SQLI_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
val withNative = sqlCallers
  .filter(_.call.code("(?i).*(nativeQuery|createNativeQuery|rawQuery).*").l.nonEmpty)
  .map(m => s"SQLI_NATIVE | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
(withConcat ++ withNative).distinct
""",
    # ── XXE 风险：XML 解析器未禁用外部实体 ──
    "xxe_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .filter(_.call.methodFullName("(?i).*(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|XMLReader|SAXReader|XMLHelper|Unmarshaller).*").l.nonEmpty)
  .filterNot(_.call.code("(?i).*(disallow-doctype-decl|external-general-entities.*false|external-parameter-entities.*false|defusedxml).*").l.nonEmpty)
  .map(m => s"XXE_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | parsers=${m.call.methodFullName.l.filter(_.matches("(?i).*(Document|SAX|XML|Transformer|Unmarshaller).*")).take(3).mkString(";")}")
  .take(40)
  .l
""",
    # ── 反序列化风险：ObjectInputStream / 不安全反序列化 ──
    "deserialization_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .filter(_.call.methodFullName("(?i).*(ObjectInputStream|readObject|readUnshared|XMLDecoder|Hessian|Kryo|enableDefaultTyping).*").l.nonEmpty)
  .filterNot(_.call.code("(?i).*(ObjectInputFilter|ValidatingObjectInputStream|resolveClass|whitelist).*").l.nonEmpty)
  .map(m => s"DESER_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.methodFullName.l.filter(_.matches("(?i).*(ObjectInput|readObject|XMLDecoder|Hessian|Kryo|enableDefaultTyping).*")).take(3).mkString(";")}")
  .take(40)
  .l
""",
    # ── 命令注入风险：Runtime.exec / ProcessBuilder ──
    "cmd_exec_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)"))
  .filter(_.call.methodFullName("(?i).*(Runtime.*exec|ProcessBuilder|getRuntime).*").l.nonEmpty)
  .filterNot(_.call.code("(?i).*(Pattern[.]matches|whitelist|allowlist|matches).*").l.nonEmpty)
  .map(m => s"CMD_EXEC_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.methodFullName.l.filter(_.matches("(?i).*(exec|ProcessBuilder|getRuntime).*")).take(3).mkString(";")}")
  .take(40)
  .l
""",
    # ── CWE-269: 权限提升 / 角色操纵 ──
    "privilege_escalation": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .where(_.code("(?i).*(role|isAdmin|privilege|permission|authority|admin|setRole|grantRole|makeAdmin|setAdmin|elevatePrivilege|updateRole|assignPermission).*"))
  .filter(_.call.code("(?i).*(setRole|grantRole|setAdmin|makeAdmin|setPermission|grantAuthority|elevateRole|updateRole|addRole|revokeRole).*").l.nonEmpty)
  .map(m => s"PRIV_ESCALATION | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(60)
  .l
""",
    # ── CWE-276: 不正确的默认权限（文件/目录/云存储） ──
    "incorrect_permissions": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .filter(_.call.code("(?i).*(chmod|chown|setReadable|setWritable|setExecutable|setPosixFilePermissions|PosixFilePermissions|fromString).*").l.nonEmpty)
  .map(m => s"PERM_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | ops=${m.call.code.l.filter(_.matches("(?i).*(chmod|chown|setReadable|setWritable|setPosix|fromString).*")).take(3).mkString(";")}")
  .take(40)
  .l
""",
    # ── CWE-307: 认证入口缺少暴力破解防护 ──
    "brute_force_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|RequestMapping)"))
  .where(_.name("(?i)(login|authenticate|signin|auth|doLogin|attemptAuthentication|handleLogin)"))
  .filterNot(_.call.code("(?i).*(RateLimit|rateLimit|throttle|captcha|reCaptcha|kaptcha|lockout|RateLimiter|Bucket4j|failedAttempt|maxAttempt|loginFailCount).*").l.nonEmpty)
  .map(m => s"BRUTE_FORCE_RISK | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # ── CWE-362: 竞态条件 / 不正确的同步 ──
    "race_condition_risk": """
import io.shiftleft.semanticcpg.language._
val deductMethods = cpg.method
  .where(_.code("(?i).*(balance|stock|inventory|quantity|coupon|credit|quota|deduct|withdraw|consume|transfer).*"))
  .filter(_.call.code("(?i).*(findById|getById|findOne|selectById|getStock|getBalance).*").l.nonEmpty)
  .filter(_.call.code("(?i).*(save|saveAndFlush|update|setStock|setBalance|saveOrUpdate).*").l.nonEmpty)
  .l
val noAtomic = deductMethods
  .filterNot(_.call.code("(?i).*(FOR UPDATE|forUpdate|selectForUpdate|AtomicInteger|AtomicReference|ReentrantLock|synchronized|RedissonClient|distributedLock|lock[(]|@Version).*").l.nonEmpty)
  .map(m => s"RACE_CONDITION | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
noAtomic
""",
    # ── CWE-384: 会话固定（登录后未轮换 Session） ──
    "session_fixation_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|RequestMapping)"))
  .where(_.name("(?i)(login|authenticate|signin|auth|doLogin|ssoCallback|oauthCallback).*"))
  .filter(_.call.code("(?i).*(getSession|setAttribute|session|login_user|JSESSIONID).*").l.nonEmpty)
  .filterNot(_.call.code("(?i).*(invalidate|changeSessionId|regenerate|sessionFixation|migrateSession|session_regenerate_id|session[.]clear).*").l.nonEmpty)
  .map(m => s"SESSION_FIXATION | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # ── CWE-521: 弱密码复杂度要求 ──
    "weak_password_requirements": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|RequestMapping)"))
  .where(_.name("(?i)(register|signup|createUser|changePassword|updatePassword|resetPassword|setPassword).*"))
  .filterNot(_.call.code("(?i).*(Passay|zxcvbn|PasswordValidator|CharacterRule|LengthRule|passwordStrength|strengthCheck).*").l.nonEmpty)
  .filterNot(_.call.code("(?i).*(length[(][)].*(>=|>)[ ]*[89]|length[(][)].*(>=|>)[ ]*1[0-9]|minLength.*[89]|min_length.*[89]).*").l.nonEmpty)
  .map(m => s"WEAK_PASSWORD | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # ── CWE-610: 外部可控引用（支付/订单金额篡改） ──
    "payment_tampering": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|RequestMapping)"))
  .where(_.code("(?i).*(price|amount|total|discount|coupon|fee|cost|payment|checkout|transfer|order).*"))
  .filter(_.call.code("(?i).*(setPrice|setAmount|setTotal|setTotalAmount|setDiscount|setFee|setShippingFee|setQuantity).*").l.nonEmpty)
  .filterNot(_.call.code("(?i).*(db[.]getPrice|productRepo[.]getPrice|itemRepo[.]getPrice|verifySign|hmac|comparePrice|recalculate|serverPrice).*").l.nonEmpty)
  .map(m => s"PAYMENT_TAMPER | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(60)
  .l
""",
    # ── CWE-613: 不充分的会话过期 ──
    "session_expiration_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.code("(?i).*(setMaxInactiveInterval|setExpiration|setMaxAge|cookie[.]setMaxAge|setSessionTimeout|Jwts[.]builder|jwt[.]exp|session[.]timeout|PERMANENT_SESSION_LIFETIME).*"))
  .map(m => s"SESSION_EXPIRATION | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # ── CWE-640: 弱密码恢复机制 ──
    "password_recovery_weakness": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|RequestMapping|GetMapping)"))
  .where(_.name("(?i)(forgotPassword|resetPassword|recover|verifyOTP|sendResetLink|securityQuestion|verifySecurityAnswer|confirmReset|handleReset).*"))
  .map(m => s"PWD_RECOVERY | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    # ── CWE-915: 批量赋值（Mass Assignment / 自动绑定敏感字段） ──
    "mass_assignment_risk": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .filter(_.parameter.annotation.name("(?i)(ModelAttribute|RequestBody)").l.nonEmpty)
  .where(_.code("(?i).*(User|Account|Profile|Member|Employee|Customer|Admin).*"))
  .filterNot(_.call.code("(?i).*(DTO|Vo|Form|setDisallowedFields|setAllowedFields|BeanUtils[.]copyProperties).*").l.nonEmpty)
  .filterNot(_.parameter.exists(p => p.annotation.name("(?i)(ModelAttribute|RequestBody)").l.nonEmpty && p.typeFullName.matches(".*[.](DTO|Dto|VO|Vo|Form|Request|Cmd).*")))
  .map(m => s"MASS_ASSIGNMENT | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(60)
  .l
""",
    # ── Recon: WebSocket 端点 ──
    "websocket_endpoints": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(ServerEndpoint|OnMessage|OnOpen|OnClose)"))
  .map(m => s"WS_ENDPOINT | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(50)
  .l
""",
    # ── Recon: 定时任务 ──
    "scheduled_tasks": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(Scheduled|Schedules)"))
  .map(m => s"SCHEDULED | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(80)
  .l
""",
    # ── Recon: 消息队列消费者 ──
    "mq_consumers": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(KafkaListener|RabbitListener|JmsListener|SqsListener|EventListener|Subscribe)"))
  .map(m => s"MQ_CONSUMER | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(80)
  .l
""",
    # ── Recon: 文件上传处理器 ──
    "file_upload_handlers": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.parameter.typeFullName("(?i).*(MultipartFile|Part|CommonsMultipartFile)"))
  .map(m => s"FILE_UPLOAD | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(50)
  .l
""",
    # ── Recon: 反序列化入口 ──
    "deserialization_entries": """
import io.shiftleft.semanticcpg.language._
val deserCalls = cpg.call
  .name("(?i)(readObject|fromXML|readValue|parseObject|parseArray|deserialize)")
  .where(_.methodFullName("(?i).*(ObjectInputStream|XStream|ObjectMapper|JSON|Gson|SnakeYAML)"))
  .map(c => s"DESER_ENTRY | caller=${c.method.fullName} | sink=${c.methodFullName} | file=${c.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(60)
  .l
deserCalls
""",
    # ── Recon: RPC 端点（gRPC / Dubbo） ──
    "rpc_endpoints": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(DubboService|GrpcService|RpcService)"))
  .map(m => s"RPC_ENDPOINT | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(50)
  .l
""",
    # ── Recon: Content-Type 消费者 ──
    "content_type_consumers": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(PostMapping|PutMapping|PatchMapping|RequestMapping)"))
  .filter(_.annotation.code.l.exists(c => c.matches("(?i).*(consumes|produces|application/xml|text/xml|application/json|multipart|form-data).*")))
  .map(m => {
    val annotCode = m.annotation.code.l.filter(c => c.matches("(?i).*(consumes|produces|application/xml|text/xml|application/json|multipart|form-data).*")).mkString(";")
    s"CONTENT_TYPE | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | types=${annotCode}"
  })
  .take(80)
  .l
""",
}

# ---------------------------------------------------------------------------
# 逻辑漏洞专用查询集（Python / Flask）
# ---------------------------------------------------------------------------
flask_logic_queries = {
    "endpoint_enumeration": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(_.name("(?i)(route|add_url_rule)"))
  .where(_.argument.code("(?i)(GET|POST|PUT|DELETE|PATCH|methods)"))
  .map(c => s"${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)} | route_args=${c.argument.code.l.take(3).mkString(",")}")
  .take(200)
  .l
""",
    "auth_guards": """
import io.shiftleft.semanticcpg.language._
val decoratorGuards = cpg.method
  .where(_.annotation.name("(?i)(login_required|requires_auth|auth_required|roles_required|role_required|requires_roles)"))
  .map(m => s"ANNOTATION_GUARD | ${m.fullName} | ${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
val codeGuards = cpg.call
  .where(_.name("(?i)(is_authenticated|login_required|requires_auth|check_auth|verify_token|authenticate)"))
  .map(c => s"CODE_GUARD | ${c.methodFullName} | caller=${c.method.fullName} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
(decoratorGuards ++ codeGuards).distinct
""",
    "sensitive_operations": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(commit|rollback|add|delete|merge|execute|executemany|fetchall|fetchone)"))
  .or(_.methodFullName("(?i).*(session|db|cursor|query|filter_by|filter|order_by|group_by).*"))
  .or(_.name("(?i)(system|popen|call|check_output|send_mail|send_email|upload_file|remove)"))
  .map(c => s"SENSITIVE_OP | ${c.name} | method=${c.methodFullName} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(150)
  .l
""",
    "idor_candidates": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(_.name("(?i)(get|query|filter_by|filter)"))
  .where(_.argument.code("(?i)(id|user_id|pk|slug)"))
  .map(c => s"IDOR_CANDIDATE | ${c.name}(${c.argument.code.l.take(3).mkString(",")}) | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(80)
  .l
""",
    "info_leak_candidates": """
import io.shiftleft.semanticcpg.language._
val errorHandlers = cpg.method
  .where(_.annotation.name("(?i)(errorhandler|app_errorhandler)"))
  .map(m => s"EXCEPTION_LEAK | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")}")
  .take(30)
  .l
val sensitiveLogs = cpg.call
  .where(_.name("(?i)(error|warning|info|debug|exception|critical)"))
  .where(_.argument.code("(?i).*(password|secret|token|key|credential)"))
  .map(c => s"SENSITIVE_LOG | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | arg=${c.argument.code.l.mkString(",").take(80)} | line=${c.lineNumber.getOrElse(0)}")
  .take(50)
  .l
(errorHandlers ++ sensitiveLogs).distinct
""",
    "hardcoded_credentials_v2": """
import io.shiftleft.semanticcpg.language._
cpg.literal
  .where(_.inAssignment.target.code("(?i).*(password|passwd|secret|secret_key|api_key|token|credential|jwt_secret|auth_key|access_key)"))
  .filter(_.code.length > 4)
  .whereNot(_.code("(?i)(null|none|empty|\\$\\{|%s|TODO|CHANGE_ME|os\\.environ|os\\.getenv)"))
  .map(lit => s"HARDCODED_CRED | value=${lit.code.take(60)} | method=${lit.inCall.method.fullName.l.headOption.getOrElse("?")} | file=${lit.file.name.headOption.getOrElse("?")} | line=${lit.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    "security_filter_chain": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(before_request|after_request|before_first_request|teardown_request)"))
  .or(_.code("(?i)(session|cookie|CORS|CSRF|X-Frame-Options|Content-Security-Policy)"))
  .map(c => s"SECURITY_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    "public_endpoints": """
import io.shiftleft.semanticcpg.language._
val allRoutes = cpg.call.where(_.name("(?i)(route|add_url_rule)"))
val guardedMethods = cpg.method.where(_.annotation.name("(?i)(login_required|requires_auth|auth_required|roles_required)"))
val guardedNames = guardedMethods.fullName.toSet
allRoutes
  .filter(c => !guardedNames.contains(c.method.fullName))
  .map(c => s"PUBLIC_ENDPOINT | ${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
""",
    "cors_config": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(CORS|cross_origin|add_header)"))
  .or(_.code("(?i)(Access-Control-Allow-Origin|CORS|cross_origin)"))
  .map(c => s"CORS_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
}

# ---------------------------------------------------------------------------
# 逻辑漏洞专用查询集（Python / Django）
# ---------------------------------------------------------------------------
django_logic_queries = {
    "endpoint_enumeration": """
import io.shiftleft.semanticcpg.language._
val urlPatterns = cpg.call
  .where(_.name("(?i)(path|re_path|url)"))
  .map(c => s"URL_PATTERN | ${c.argument.code.l.take(3).mkString(",")} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(200)
  .l
val apiViews = cpg.method
  .where(_.annotation.name("(?i)(api_view|action|permission_classes)"))
  .map(m => s"API_VIEW | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
(urlPatterns ++ apiViews).distinct
""",
    "auth_guards": """
import io.shiftleft.semanticcpg.language._
val decoratorGuards = cpg.method
  .where(_.annotation.name("(?i)(login_required|permission_required|permission_classes|staff_member_required|user_passes_test|IsAuthenticated|IsAdminUser)"))
  .map(m => s"ANNOTATION_GUARD | ${m.fullName} | ${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
val codeGuards = cpg.call
  .where(
    _.name("(?i)(is_authenticated|has_perm|check_permissions|has_permission)"))
  .or(_.code("(?i)(request\\.user\\.is_authenticated|request\\.user\\.is_staff|request\\.user\\.is_superuser)"))
  .map(c => s"CODE_GUARD | ${c.methodFullName} | caller=${c.method.fullName} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
(decoratorGuards ++ codeGuards).distinct
""",
    "sensitive_operations": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(save|delete|create|update|bulk_create|bulk_update|raw|execute|cursor)"))
  .or(_.methodFullName("(?i).*(objects|Manager|QuerySet|filter|exclude|get|aggregate|annotate).*"))
  .or(_.name("(?i)(send_mail|send_mass_mail|upload_to|remove|system)"))
  .map(c => s"SENSITIVE_OP | ${c.name} | method=${c.methodFullName} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(150)
  .l
""",
    "idor_candidates": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(get|get_object_or_404|get_object_or_None|filter)"))
  .where(_.argument.code("(?i)(id|pk|slug|user_id|owner_id)"))
  .map(c => s"IDOR_CANDIDATE | ${c.name}(${c.argument.code.l.take(3).mkString(",")}) | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(80)
  .l
""",
    "info_leak_candidates": """
import io.shiftleft.semanticcpg.language._
val sensitiveLogs = cpg.call
  .where(_.name("(?i)(error|warning|info|debug|exception|critical)"))
  .where(_.argument.code("(?i).*(password|secret|token|key|credential|SECRET_KEY)"))
  .map(c => s"SENSITIVE_LOG | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | arg=${c.argument.code.l.mkString(",").take(80)} | line=${c.lineNumber.getOrElse(0)}")
  .take(50)
  .l
sensitiveLogs.distinct
""",
    "hardcoded_credentials_v2": """
import io.shiftleft.semanticcpg.language._
cpg.literal
  .where(_.inAssignment.target.code("(?i).*(SECRET_KEY|PASSWORD|API_KEY|TOKEN|CREDENTIAL|AUTH_KEY|ACCESS_KEY|DATABASES)"))
  .filter(_.code.length > 4)
  .whereNot(_.code("(?i)(null|none|empty|\\$\\{|%s|TODO|CHANGE_ME|os\\.environ|os\\.getenv|getenv|environ)"))
  .map(lit => s"HARDCODED_CRED | value=${lit.code.take(60)} | method=${lit.inCall.method.fullName.l.headOption.getOrElse("?")} | file=${lit.file.name.headOption.getOrElse("?")} | line=${lit.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    "security_filter_chain": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.code("(?i)(MIDDLEWARE|AUTHENTICATION_BACKENDS|DEFAULT_PERMISSION_CLASSES|CSRF|SESSION_|CORS_|SECURE_|ALLOWED_HOSTS)"))
  .map(c => s"SECURITY_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    "public_endpoints": """
import io.shiftleft.semanticcpg.language._
val apiViews = cpg.method.where(_.annotation.name("(?i)(api_view|action)"))
val guardedViews = cpg.method.where(_.annotation.name("(?i)(permission_classes|login_required|permission_required|IsAuthenticated)"))
val guardedNames = guardedViews.fullName.toSet
apiViews
  .filter(m => !guardedNames.contains(m.fullName))
  .where(!_.code("(?i)(AllowAny|IsAuthenticatedOrReadOnly)"))
  .map(m => s"PUBLIC_ENDPOINT | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(100)
  .l
""",
    "cors_config": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.code("(?i)(CORS_|corsheaders|Access-Control-Allow-Origin|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOWED_ORIGINS)"))
  .map(c => s"CORS_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
}

# ---------------------------------------------------------------------------
# 逻辑漏洞专用查询集（JavaScript / Express）
# ---------------------------------------------------------------------------
express_logic_queries = {
    "endpoint_enumeration": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(get|post|put|delete|patch|all|use)"))
  .where(_.argument.code("(?i)(\\/|router|app|express)"))
  .map(c => s"${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)} | route=${c.argument.code.l.headOption.getOrElse("?")}")
  .take(200)
  .l
""",
    "auth_guards": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(authenticate|authorize|verify|isAuthenticated|ensureAuthenticated|requireAuth|requireLogin|checkAuth)"))
  .or(_.code("(?i)(passport|jwt|jsonwebtoken|bcrypt|session|req\\.user|req\\.isAuthenticated)"))
  .map(c => s"CODE_GUARD | ${c.name} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
""",
    "sensitive_operations": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(query|exec|execute|save|delete|update|create|remove|insert|findOne|findById|findAll)"))
  .or(_.methodFullName("(?i).*(sequelize|mongoose|knex|typeorm|prisma|sqlite|pg|mysql).*"))
  .or(_.name("(?i)(sendFile|unlink|writeFile|readFile|exec|execSync|spawn|sendMail)"))
  .map(c => s"SENSITIVE_OP | ${c.name} | method=${c.methodFullName} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(150)
  .l
""",
    "idor_candidates": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(findById|findOne|findByPk|find)"))
  .where(_.argument.code("(?i)(req\\.params|req\\.query|req\\.body|id|userId)"))
  .map(c => s"IDOR_CANDIDATE | ${c.name}(${c.argument.code.l.take(3).mkString(",")}) | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(80)
  .l
""",
    "info_leak_candidates": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(error|warn|info|debug|log)"))
  .where(_.argument.code("(?i).*(password|secret|token|key|credential|apiKey)"))
  .map(c => s"SENSITIVE_LOG | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | arg=${c.argument.code.l.mkString(",").take(80)} | line=${c.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    "hardcoded_credentials_v2": """
import io.shiftleft.semanticcpg.language._
cpg.literal
  .where(_.inAssignment.target.code("(?i).*(password|passwd|secret|apiKey|api_key|token|credential|privateKey|private_key|authKey|accessKey|secretKey|jwtSecret|sessionSecret)"))
  .filter(_.code.length > 4)
  .whereNot(_.code("(?i)(null|undefined|empty|process\\.env|\\$\\{|TODO|CHANGE_ME)"))
  .map(lit => s"HARDCODED_CRED | value=${lit.code.take(60)} | method=${lit.inCall.method.fullName.l.headOption.getOrElse("?")} | file=${lit.file.name.headOption.getOrElse("?")} | line=${lit.lineNumber.getOrElse(0)}")
  .take(50)
  .l
""",
    "security_filter_chain": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(helmet|cors|csrf|rateLimit|express-session|cookie-session|hpp|mongoSanitize)"))
  .or(_.code("(?i)(helmet|cors|csrf|rateLimit|express\\.session|cookieParser)"))
  .map(c => s"SECURITY_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
    "public_endpoints": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(get|post|put|delete|patch)"))
  .where(_.argument.code("(?i)(\\/)"))
  .where(!_.argument.code("(?i)(authenticate|authorize|verify|ensureAuth|requireAuth|checkAuth)"))
  .map(c => s"PUBLIC_ENDPOINT | ${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
""",
    "cors_config": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(cors|setHeader)"))
  .or(_.code("(?i)(Access-Control-Allow-Origin|cors|CORS)"))
  .map(c => s"CORS_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
}

# ---------------------------------------------------------------------------
# 逻辑漏洞通用查询集（框架无关，适用于 SCA 场景的用户自写代码）
# 不依赖任何框架注解，用 Servlet API / JDBC / 文件 IO 等通用模式检测
# ---------------------------------------------------------------------------
generic_logic_queries = {
    # 通用 HTTP 入口枚举（Servlet / Handler / 任何接收 HTTP 请求的方法）
    "endpoint_enumeration": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(
    _.name("(?i)(doGet|doPost|doPut|doDelete|service|handleRequest|handle|invoke|process)"))
  .or(_.parameter.typeFullName("(?i).*(HttpServletRequest|HttpServletResponse|Request|Response|Context|Exchange).*"))
  .or(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping|Path|WebEndpoint|route)"))
  .map(m => s"${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | params=${m.parameter.name.l.mkString(",")}")
  .take(200)
  .l
""",
    # 通用鉴权守卫（任何语言/框架的常见鉴权模式 + Shiro/JAX-RS）
    "auth_guards": """
import io.shiftleft.semanticcpg.language._
val codeGuards = cpg.call
  .where(
    _.name("(?i)(isAuthenticated|hasRole|hasPermission|checkPermission|authorize|requireAuth|isAdmin|isAuthorized|authenticate|verify|checkAuth|login_required|require_login|ensure_auth)"))
  .or(_.code("(?i)(is_authenticated|has_perm|check_auth|verify_token|getAuthentication|getPrincipal|current_user)"))
  .map(c => s"CODE_GUARD | ${c.name} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
val shiroGuards = cpg.method
  .where(_.annotation.name("(?i)(RequiresAuthentication|RequiresPermissions|RequiresRoles|RequiresUser)"))
  .map(m => s"SHIRO_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(60)
  .l
val jaxrsGuards = cpg.method
  .where(_.annotation.name("(?i)(RolesAllowed|PermitAll|DenyAll)"))
  .map(m => s"JAXRS_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(60)
  .l
(codeGuards ++ shiroGuards ++ jaxrsGuards).distinct
""",
    # Apache Shiro：注解 + Subject 代码守卫（与 java_logic_queries 同构）
    "shiro_auth_guards": """
import io.shiftleft.semanticcpg.language._
val shiroAnnot = cpg.method
  .where(_.annotation.name("(?i)(RequiresAuthentication|RequiresPermissions|RequiresRoles|RequiresUser|RequiresGuest)"))
  .map(m => s"SHIRO_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(80)
  .l
val shiroCode = cpg.call
  .where(_.methodFullName("(?i).*(SecurityUtils[.]getSubject|Subject[.]isAuthenticated|Subject[.]isPermitted|Subject[.]hasRole|subject[.]isPermitted|subject[.]hasRole)"))
  .map(c => s"SHIRO_CODE_GUARD | caller=${c.method.fullName} | line=${c.lineNumber.getOrElse(0)}")
  .take(80)
  .l
(shiroAnnot ++ shiroCode).distinct
""",
    # JAX-RS / Jakarta REST 声明式鉴权
    "jaxrs_auth_guards": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.annotation.name("(?i)(RolesAllowed|PermitAll|DenyAll)"))
  .map(m => s"JAXRS_ANNOTATION_GUARD | ${m.fullName} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(100)
  .l
""",
    # 通用敏感操作（DB / 文件 / 网络 / 系统命令）
    "sensitive_operations": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(save|delete|update|remove|insert|execute|create|drop|alter|grant|revoke|transfer|withdraw|deposit|payment|send|publish)"))
  .or(_.methodFullName("(?i).*(Statement|PreparedStatement|Connection|Session|Transaction|Repository|Dao|Mapper|JdbcTemplate|EntityManager).*"))
  .or(_.name("(?i)(system|exec|popen|spawn|writeFile|readFile|sendFile|unlink|mkdir|rmdir|upload|download)"))
  .or(_.methodFullName("(?i).*(Runtime|ProcessBuilder|subprocess|os[.]system|child_process|fs[.]write).*"))
  .map(c => s"SENSITIVE_OP | ${c.name} | method=${c.methodFullName} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(200)
  .l
""",
    # 通用 IDOR 候选（任何通过 ID 查询/修改资源的地方）
    "idor_candidates": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.name("(?i)(findById|getById|findOne|deleteById|updateById|getOne|get|query|filter|fetch)"))
  .where(_.argument.code("(?i)(id|Id|ID|user_id|userId|pk|slug|key|recordId)"))
  .map(c => s"IDOR_CANDIDATE | ${c.name}(${c.argument.code.l.take(3).mkString(",")}) | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(100)
  .l
""",
    # 通用信息泄露（日志 / 异常 / 响应泄露敏感数据）
    "info_leak_candidates": """
import io.shiftleft.semanticcpg.language._
val sensitiveLogs = cpg.call
  .where(
    _.name("(?i)(error|warn|info|debug|log|print|println|echo|console|write|send|respond)"))
  .where(_.argument.code("(?i).*(password|secret|token|key|credential|ssn|credit|email|phone|account|private).*"))
  .map(c => s"SENSITIVE_LOG | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | arg=${c.argument.code.l.mkString(",").take(80)} | line=${c.lineNumber.getOrElse(0)}")
  .take(80)
  .l
sensitiveLogs.distinct
""",
    # 通用硬编码凭证
    "hardcoded_credentials_v2": """
import io.shiftleft.semanticcpg.language._
cpg.literal
  .where(_.inAssignment.target.code("(?i).*(password|passwd|pwd|secret|apiKey|api_key|token|credential|privateKey|private_key|authKey|accessKey|secretKey|connectionString|awsKey|clientSecret|jwtSecret|sessionSecret|db_password|database_password)"))
  .filter(_.code.length > 4)
  .whereNot(_.code("(?i)(null|none|undefined|empty|\\$\\{|%s|TODO|CHANGE_ME|xxx|os[.]environ|os[.]getenv|process[.]env|System[.]getenv|getProperty)"))
  .map(lit => s"HARDCODED_CRED | value=${lit.code.take(60)} | method=${lit.inCall.method.fullName.l.headOption.getOrElse("?")} | file=${lit.file.name.headOption.getOrElse("?")} | line=${lit.lineNumber.getOrElse(0)}")
  .take(80)
  .l
""",
    # 通用安全配置审计
    "security_filter_chain": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.code("(?i)(permitAll|authenticated|authorize|csrf|cors|session|cookie|Access-Control|X-Frame|Content-Security|MIDDLEWARE|FILTER)"))
  .map(c => s"SECURITY_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(60)
  .l
""",
    # Apache Shiro 配置（filterChain / SecurityManager）
    "shiro_security_config": """
import io.shiftleft.semanticcpg.language._
cpg.method
  .where(_.code("(?i).*(ShiroFilterFactoryBean|filterChainDefinitions|filterChainDefinitionMap|SecurityUtils|shiro[.]ini|DefaultWebSecurityManager)"))
  .map(m => s"SHIRO_CONFIG | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | code_preview=${m.code.take(200)}")
  .take(30)
  .l
""",
    # JAX-RS 无声明式鉴权的资源入口
    "jaxrs_unprotected_resources": """
import io.shiftleft.semanticcpg.language._
val jaxrsEndpoints = cpg.method
  .where(_.annotation.name("(?i)(Path|GET|POST|PUT|DELETE|PATCH|HttpMethod)"))
  .l
val jaxrsGuarded = cpg.method
  .where(_.annotation.name("(?i)(RolesAllowed|PermitAll|DenyAll)"))
  .fullName.toSet
jaxrsEndpoints
  .filter(m => !jaxrsGuarded.contains(m.fullName))
  .map(m => s"JAXRS_UNPROTECTED | caller=${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)} | annotations=${m.annotation.name.l.mkString(",")}")
  .take(80)
  .l
""",
    # 通用公开端点（无鉴权守卫的入口方法）
    "public_endpoints": """
import io.shiftleft.semanticcpg.language._
val allEntries = cpg.method
  .where(
    _.name("(?i)(doGet|doPost|doPut|doDelete|service|handleRequest|handle|invoke|process)"))
  .or(_.parameter.typeFullName("(?i).*(HttpServletRequest|HttpServletResponse|Request|Response|Context|Exchange).*"))
  .or(_.annotation.name("(?i)(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping|Path|route)"))
val guardedMethods = cpg.method
  .where(_.code("(?i)(isAuthenticated|hasRole|checkAuth|authorize|requireAuth|verify|authenticate|login_required|is_authenticated)"))
val guardedNames = guardedMethods.fullName.toSet
allEntries
  .filter(m => !guardedNames.contains(m.fullName))
  .map(m => s"PUBLIC_ENDPOINT | ${m.fullName} | file=${m.file.name.headOption.getOrElse("?")} | line=${m.lineNumber.getOrElse(0)}")
  .take(100)
  .l
""",
    # 通用 CORS 配置
    "cors_config": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .where(
    _.code("(?i)(Access-Control-Allow-Origin|CORS|cors|CrossOrigin|allowedOrigins|setHeader.*Origin)"))
  .map(c => s"CORS_CONFIG | ${c.name} | code=${c.code.take(120)} | caller=${c.method.fullName} | file=${c.method.file.name.headOption.getOrElse("?")} | line=${c.lineNumber.getOrElse(0)}")
  .take(40)
  .l
""",
}


cpp_auxiliary_queries = {
    "cpp_indirect_dispatch_sites": """
import io.shiftleft.semanticcpg.language._
cpg.call
  .filter(_.dispatchType != "STATIC_DISPATCH")
  .take(80)
  .code
  .l
""",
    "cpp_indirect_sensitive_sinks": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("memcpy|memmove|strcpy|strcat|sprintf|snprintf|strncpy|read|write")
  .filter(_.dispatchType != "STATIC_DISPATCH")
  .take(40)
  .code
  .l
''',
}


def is_reflection_query_type(query_name: str) -> bool:
    """是否为 Java 反射保守查询（分析流程与污点流不同）。"""
    return query_name.startswith("java_reflection")


# C/C++ 的默认查询集：
# 这里保留了偏 mbedtls / crypto 栈风格的文件过滤，适合原始老项目复刻。
cpp_queries = {
    "cpp_buffer_overflow": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("memcpy|memmove|strcpy|strcat|sprintf|snprintf|strncpy|gets|scanf|sscanf")
    .where(_.method.file.name(".*(ssl_tls|x509|asn1|pk|ecdsa|ssl_tls13).*"))
    .reachableByFlows(cpg.parameter.name("buf|data|input|payload|len|size|buflen"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    "cpp_mbedtls_custom_mem": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("mbedtls_.*(mem|copy|move|alloc|free|calloc|realloc|zeroize_and_free)")
    .where(_.method.file.name(".*(ssl_tls|x509|asn1|ssl_tls13).*"))
    .reachableByFlows(cpg.parameter.name("buf|data|input|payload|psk|secret"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_use_after_free": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("free|delete|delete\\\\[\\\\]|mbedtls_free|mbedtls_asn1_free_named_data_list|mbedtls_asn1_free|mbedtls_zeroize_and_free")
    .where(_.method.file.name(".*(ssl_tls|x509|asn1|ssl_tls13).*"))
    .reachableByFlows(cpg.identifier)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_unsafe_alloc": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("malloc|calloc|realloc|kmalloc|vmalloc|mbedtls_calloc|mbedtls_malloc")
    .where(_.method.file.name(".*(ssl_tls|x509|asn1|ssl_tls13).*"))
    .argument(1)
    .reachableByFlows(cpg.parameter.name("len|size|buflen|input_len"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_null_deref": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("<operator>.memberAccess|<operator>.indirectMemberAccess|fieldAccess")
    .where(_.method.file.name(".*(ssl_tls|x509|asn1|ssl_tls13).*"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_can_or_buffer_parsing": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("memcpy|memmove|strncpy|strcpy|snprintf")
    .where(_.method.file.name(".*ssl_tls.*"))
    .where(_.code(".*(buf|payload|peer_cid|certificate_request_context|in_buf|out_buf).*"))
    .reachableByFlows(cpg.parameter.name("buf|data|len|peer_cid_len"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    "cpp_integer_overflow": f'''
import io.shiftleft.semanticcpg.language._
cpg.call.name("malloc|calloc|realloc|memcpy|memmove")
    .where(_.method.file.name(".*(ssl_tls|x509|asn1|ssl_tls13).*"))
    .where(_.argument.code(".*(\\\\+|\\\\*|<<).*"))
    .reachableByFlows(cpg.parameter.name("len|size"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(8).p
''',
}

# C/C++ 的通用查询集：
# 与默认查询相比，尽量减少 vendor/file pattern 限制，用于更泛化的源码扫描。
cpp_queries_generic = {
    "cpp_buffer_overflow": f'''
cpg.call.name("memcpy|memmove|strcpy|strcat|sprintf|snprintf|strncpy|gets|scanf|sscanf")
    .reachableByFlows(cpg.parameter.name("buf|data|input|payload|len|size|buflen|src|dst|count|n"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    "cpp_custom_mem": f'''
cpg.call.name(".*_(mem|copy|move|alloc|free|calloc|realloc|zeroize|destroy|release|dispose|cleanup)")
    .reachableByFlows(cpg.parameter.name("buf|data|input|payload|psk|secret|key|ctx|ptr|block|chunk"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_use_after_free": f'''
cpg.call.name("free|delete|delete\\\\[\\\\]|.*_free|.*_release|.*_destroy|.*_dispose")
    .reachableByFlows(cpg.identifier)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_unsafe_alloc": f'''
cpg.call.name("malloc|calloc|realloc|kmalloc|vmalloc|.*_calloc|.*_malloc|.*_alloc|new|new\\\\[\\\\]")
    .argument(1)
    .reachableByFlows(cpg.parameter.name("len|size|buflen|input_len|count|nbytes|nmemb"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_null_deref": f'''
cpg.call.name("<operator>.memberAccess|<operator>.indirectMemberAccess|fieldAccess")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_can_or_buffer_parsing": f'''
cpg.call.name("memcpy|memmove|strncpy|strcpy|snprintf")
    .where(_.code(".*(buf|payload|frame|packet|header|input|data|in_buf|out_buf|msg|record).*"))
    .reachableByFlows(cpg.parameter.name("buf|data|len|size|payload_len|msg_len|count"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    "cpp_integer_overflow": f'''
cpg.call.name("malloc|calloc|realloc|memcpy|memmove")
    .where(_.argument.code(".*(\\\\+|\\\\*|<<).*"))
    .reachableByFlows(cpg.parameter.name("len|size|count|n|nbytes"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(8).p
''',
    "cpp_format_string": f'''
cpg.call.name("printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|syslog|NSLog")
    .where(_.argument.code(".*(fmt|format|msg|message|str|buf|data|input|user|argv|query|name).*"))
    .reachableByFlows(cpg.parameter.name("fmt|format|msg|message|str|buf|data|input|user_input"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_command_injection": f'''
cpg.call.name("system|popen|execl|execlp|execle|execv|execvp|execvpe|fork|spawnl|spawnv|CreateProcess|ShellExecute")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_race_condition": f'''
cpg.call
    .where(_.name("access|stat|lstat|fopen|open|creat|unlink|rename|chmod|chown|mkdir|rmdir|link|symlink"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_path_traversal": f'''
cpg.call.name("fopen|open|openat|ifstream|ofstream|fstream|stat|lstat|access|realpath|readlink")
    .reachableByFlows(cpg.parameter.name("path|filename|filepath|fname|name|dir|file_path|pathname"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_weak_crypto": f'''
cpg.call.name("rand|srand|random|drand48|lrand48|time|MD5|MD5_Init|SHA1|SHA1_Init|DES_.*|RC4|rc4")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_temp_file": f'''
cpg.call.name("mktemp|tmpnam|tempnam|tmpfile|mkstemp|mkdtemp")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(8).p
''',
    "cpp_uninit_read": f'''
cpg.call
    .where(_.name("memcpy|memmove|strcpy|strncpy|printf|fprintf|write|send|read|recv"))
    .reachableByFlows(cpg.local.name(".*"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_signal_handler": f'''
cpg.call.name("signal|sigaction|sigset|bsd_signal")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(8).p
''',
    "cpp_type_confusion": f'''
cpg.call
    .where(_.name(".*(reinterpret_cast|static_cast|const_cast|dynamic_cast).*")
           .or(_.code(".*(void\\\\s*\\\\*|char\\\\s*\\\\*|int\\\\s*\\\\*|reinterpret_cast|static_cast|const_cast|dynamic_cast).*")))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_hardcoded_secret": f'''
cpg.call
    .where(_.code(".*(?i)(password|passwd|secret|api_key|apikey|token|credential|private_key|aes_key|des_key|encryption_key|auth_key).*=.*\\\"[^\\\"]{3,}\\\".*"))
    .take(20)
    .code
    .l
''',
    "cpp_dangerous_func": f'''
cpg.call.name("alloca|gets|mktemp|tmpnam|strcpy|strcat|sprintf|vsprintf|scanf|sscanf|fscanf|vscanf|vsscanf|vfscanf")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "cpp_double_free": f'''
cpg.call.name("free|.*_free|.*_release|.*_destroy")
    .reachableByFlows(cpg.call.name("free|.*_free|.*_release|.*_destroy"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(8).p
''',
    # 分配结果经赋值流向 return，且路径上未经过 free 类调用（启发式漏检，需 LLM 复核是否在其他路径释放）
    "cpp_memory_leak": f'''
cpg.call.name("malloc|calloc|realloc|strdup|kmalloc|kzalloc|vmalloc|.*_malloc|.*_calloc")
    .filter(_.method.ast.isCall.name("free|.*_free|.*_release|.*_destroy|kfree|mbedtls_free").isEmpty)
    .dedup
    .take(15).p
''',
    # 纯下标/指针算术访问：不依赖 memcpy 等库函数名
    "cpp_array_index_oob": f'''
cpg.call.name("<operator>.indirectIndexAccess|<operator>.indexAccess|<operator>.pointerArithmetic|<operator>.indirectPointerArithmetic")
    .reachableByFlows(cpg.parameter.name("index|idx|i|j|n|len|length|size|offset|count|num|nr|slot|pos"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    # 释放点与 pthread/mutex/irq 等并发原语共现 + 指针仍可达（静态竞态/UAF 风险，需动态验证）
    "cpp_concurrent_uaf_risk": f'''
cpg.method
    .where(_.ast.isCall.name(".*(pthread_|mutex_|lock|unlock|atomic_|rwlock|spin_|irq|ISR|interrupt).*"))
    .where(_.ast.isCall.name("free|delete|.*_free|.*_release|.*_destroy"))
    .take(10)
    .dumpRaw
''',
}

# 嵌入式 / 固件相关查询集：
# 会更关注协议解析、IOCTL/MMIO、固件升级、硬件接口等模式。
cpp_queries_embedded = {
    "embedded_buffer_parsing": f'''
cpg.call.name("memcpy|memmove|strncpy|strcpy|snprintf|sscanf|fread")
    .where(_.code(".*(can|iso_tp|iso|uds|uart|spi|i2c|frame|packet|header|payload).*"))
    .reachableByFlows(cpg.parameter.name("buf|data|payload|len|size"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    "embedded_protocol_reassembly": f'''
cpg.call
    .where(_.code(".*(reassemble|segment|iso_tp|can|ud s|frame).*"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_ioctl_mmio": f'''
cpg.call.methodFullName(".*(ioctl|mmap|open|read|write|pread|pwrite).*")
    .where(_.code(".*(mmio|ioctl|device|dev|register|reg|bar|iomem).*"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(12).p
''',
    "embedded_firmware_update": f'''
cpg.call
    .where(_.code(".*(firmware|ota|update|upgrade|flash_write|boot|bootloader).*"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_crypto_misuse": f'''
cpg.call.name("rand|srand|time|get_random|RAND_bytes|MD5|SHA1|SHA256|AES_.*")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_interrupt_shared_state": f'''
cpg.call
    .where(_.code(".*(request_irq|irq_register|enable_irq|disable_irq|ISR|interrupt).*"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_command_injection": f'''
cpg.call.name("system|popen|execl|execlp|execle|execv|execvp|execvpe|fork|spawnl|spawnv")
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_format_string": f'''
cpg.call.name("printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|vsnprintf|syslog")
    .reachableByFlows(cpg.parameter.name("fmt|format|msg|message|str|buf|data|input"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_race_condition": f'''
cpg.call
    .where(_.name("access|stat|lstat|fopen|open|creat|unlink|rename|chmod|chown"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
    "embedded_path_traversal": f'''
cpg.call.name("fopen|open|openat|stat|lstat|access|realpath|readlink")
    .reachableByFlows(cpg.parameter.name("path|filename|filepath|fname|name|dir|file_path"))
    .filter(_.elements.size <= {MAX_PATH_LEN})
    .dedup
    .take(10).p
''',
}


def merge_query_dicts(*packs: dict) -> dict:
    """合并多组 Joern 查询（后者同名 key 覆盖前者）。"""
    merged: dict = {}
    for pack in packs:
        if pack:
            merged.update(pack)
    return merged


# C/C++ 统一扫描包：generic（含新增内存类） + embedded（固件/协议），不再二选一。
cpp_queries_merged = merge_query_dicts(cpp_queries_generic, cpp_queries_embedded)

# 重查询：更易触发 Joern OOM/长耗时，排在批次后部执行。
CPP_QUERY_HEAVY = frozenset(
    {
        "cpp_use_after_free",
        "cpp_double_free",
        "cpp_memory_leak",
        "cpp_uninit_read",
        "cpp_concurrent_uaf_risk",
        "cpp_custom_mem",
        "embedded_protocol_reassembly",
        "embedded_interrupt_shared_state",
    }
)

# 轻量优先顺序（未列出的 key 排在 heavy 之前、已列之后）。
CPP_QUERY_ORDER_LIGHT_FIRST = [
    "cpp_hardcoded_secret",
    "cpp_dangerous_func",
    "cpp_temp_file",
    "cpp_signal_handler",
    "cpp_weak_crypto",
    "cpp_format_string",
    "cpp_command_injection",
    "cpp_path_traversal",
    "cpp_race_condition",
    "cpp_integer_overflow",
    "cpp_null_deref",
    "cpp_buffer_overflow",
    "cpp_can_or_buffer_parsing",
    "cpp_array_index_oob",
    "cpp_unsafe_alloc",
    "cpp_type_confusion",
    "embedded_buffer_parsing",
    "embedded_ioctl_mmio",
    "embedded_firmware_update",
    "embedded_crypto_misuse",
    "embedded_command_injection",
    "embedded_format_string",
    "embedded_race_condition",
    "embedded_path_traversal",
    "cpp_use_after_free",
    "cpp_double_free",
    "cpp_memory_leak",
    "cpp_uninit_read",
    "cpp_concurrent_uaf_risk",
    "cpp_custom_mem",
    "embedded_protocol_reassembly",
    "embedded_interrupt_shared_state",
]


def order_cpp_query_map(query_map: dict) -> dict:
    """按轻→重排序，降低前几类失败时拖死整批的概率，并给 Joern 预热时间。"""
    ordered: dict = {}
    for key in CPP_QUERY_ORDER_LIGHT_FIRST:
        if key in query_map:
            ordered[key] = query_map[key]
    for key, value in query_map.items():
        if key not in ordered:
            ordered[key] = value
    return ordered


def get_cpp_scan_phases() -> List[tuple]:
    """
    分阶段扫描：先 generic 再 embedded，阶段间可 sleep 让 Joern/GC 喘息。

    Returns:
        [(phase_name, query_dict), ...]
    """
    return [
        ("cpp_generic", dict(cpp_queries_generic)),
        ("cpp_embedded", dict(cpp_queries_embedded)),
    ]


def get_expansion_query(vuln_type: str, llm_response: dict, current_max_len: int = 10) -> str:
    """
    根据 LLM 对“上下文不足点”的判断，自动生成下一步扩展查询。

    调用时机：单条 flow 上，**硬回溯已完成**且 sufficiency_check 为 false，
    且模型未提供可执行的 follow_up_query 时（审计 query_source=llm_template_expansion）。

    与硬回溯的区别：本函数不按固定 caller BFS 向上，而是按 expansion_intent
    （view_method_body / trace_upstream / check_sanitization 等）生成**定向** DSL。

    Args:
        vuln_type: 当前分析的漏洞类型名。
        llm_response: `_check_context_sufficiency` 返回的结构化 JSON。
        current_max_len: 当前路径深度上限。生成扩展查询时会根据置信度动态上调。

    Returns:
        一条可直接发送给 Joern 的 DSL。
    """
    import os
    import re

    def escape_joern_string_literal(value: str) -> str:
        """转义可嵌入 Joern 查询字符串字面量的文本。"""
        return str(value).replace("\\", "\\\\").replace('"', '\\"')

    # LLM 可能会返回“建议扩展意图”，例如追调用者、看方法体、查变量定义。
    # 这一步不是直接相信模型，而是把模型建议映射到“可控的固定查询模板”。
    intent = llm_response.get("expansion_intent", "default")
    params = llm_response.get("intent_params", {}) or {}
    confidence = float(llm_response.get("confidence", 0) or 0)
    missing = llm_response.get("missing_context_type", []) or []
    hints = llm_response.get("expansion_hints", []) or []
    target_method_name = (params.get("method_name") or "").strip()
    target_variable_name = (params.get("variable_name") or "").strip()

    # 当模型置信度越高，说明它对缺什么上下文越明确，可安全提高扩展深度。
    increment = 2 + int(confidence * 4)
    max_len = min(current_max_len + increment, 16)

    known_intents = {"trace_upstream", "view_method_body", "find_variable_def", "check_sanitization", "trace_forward", "default"}
    if not isinstance(intent, str) or intent not in known_intents:
        # 当模型没有严格按预期输出 token 时，用 hints/params 做一层启发式纠偏，
        # 尽量避免因为输出格式轻微跑偏而完全无法生成扩展查询。
        intent_lower = str(intent).lower() if intent is not None else ""
        hints_text = " ".join(hints).lower() if hints else ""
        missing_text = " ".join(missing).lower() if missing else ""

        if params.get("method_name") or "方法体" in hints_text or "method" in hints_text or "方法" in hints_text:
            intent = "view_method_body"
        elif params.get("variable_name") or "追踪参数" in hints_text or "变量" in hints_text or "definition" in hints_text:
            intent = "find_variable_def"
        elif (
            "过滤" in hints_text
            or "sanitize" in hints_text
            or "sanitization" in missing_text
            or "校验" in hints_text
            or "白名单" in hints_text
            or "认证" in hints_text
            or "边界" in hints_text
            or "范围" in hints_text
            or "bounds" in hints_text
            or "length" in hints_text
            or "validate" in hints_text
            or "verify" in hints_text
            or "auth" in hints_text
        ):
            intent = "check_sanitization"
        elif "上游" in hints_text or "caller" in hints_text or "upstream" in missing_text:
            intent = "trace_upstream"
        elif "forward" in intent_lower or "after" in hints_text or "之后" in hints_text or "释放后" in hints_text or "free后" in hints_text:
            intent = "trace_forward"
        elif "view" in intent_lower or "find" in intent_lower or "trace" in intent_lower or "sanit" in intent_lower:
            if "view" in intent_lower or "method" in intent_lower:
                intent = "view_method_body"
            elif "find" in intent_lower or "var" in intent_lower:
                intent = "find_variable_def"
            elif "sanit" in intent_lower or "filter" in intent_lower:
                intent = "check_sanitization"
            elif "trace" in intent_lower or "upstream" in intent_lower:
                intent = "trace_upstream"
            else:
                intent = "default"
        else:
            intent = "default"

    default_file_filter = os.environ.get(
        "JOERN_DEFAULT_FILE_PATTERN",
        ".*",
    )
    # 文件过滤优先级：
    # 1. LLM 明确指定
    # 2. 当前响应里的 intent_params
    # 3. 环境变量默认值
    file_filter = (
        params.get("file_pattern")
        or llm_response.get("intent_params", {}).get("file_pattern")
        or default_file_filter
    )

    if params.get("scope") == "generic" or os.environ.get("JOERN_FORCE_GENERIC", "0") == "1":
        # generic 模式强调全库召回率，因此不再收窄文件范围。
        file_filter = ".*"

    embedded_tags = params.get("hw_tags") or llm_response.get("intent_params", {}).get("hw_tags")
    if params.get("scope") == "embedded" or embedded_tags:
        if isinstance(embedded_tags, (list, tuple)) and embedded_tags:
            # 如果模型给出了硬件/协议标签，就按标签拼出更有针对性的文件过滤模式。
            file_filter = fr'.*({"|".join(re.escape(tag) for tag in embedded_tags)}).*'
        else:
            file_filter = r".*(can|iso|iso_tp|uds|uart|spi|i2c|boot|firmware|ota|mmio|ioctl).*"

    if intent == "trace_upstream":
        # 追溯上游调用链时，优先锚定到当前嫌疑方法的 caller，
        # 这样拿回来的上下文更接近当前可疑路径，而不是重新全库广搜。
        if target_method_name:
            escaped_method_name = escape_joern_string_literal(target_method_name)
            return f"""
            cpg.method.name("{escaped_method_name}")
            .caller
            .where(_.file.name("{file_filter}"))
            .take(4)
            .dumpRaw
            """

        # 如果模型没指出具体方法，不再回退到全库 reachableByFlows（必超时），
        # 改为查询文件内的调用关系摘要（廉价查询）。
        return (
            'cpg.call'
            '.where(_.method.file.name("' + file_filter + '"))'
            '.whereNot(_.method.name("<global>"))'
            '.take(8)'
            '.map(c => c.method.name + ":" + c.lineNumber + " -> " + c.code)'
            '.dedup'
            '.l'
        )

    if intent == "view_method_body" and params.get("method_name"):
        # 查看完整方法体：相比只看 AST 局部节点，完整方法体更适合发现分支、防御逻辑和前置约束。
        method_name = escape_joern_string_literal(params["method_name"])
        return f"""
        cpg.method.name("{method_name}")
        .take(3)
        .dumpRaw
        """

    if intent == "find_variable_def" and params.get("variable_name"):
        # 查变量定义时，不再只返回零散 AST 片段，而是优先返回“包含该变量的完整方法体”，
        # 便于 LLM 看清赋值、检查、再赋值和最终进入 sink 的全过程。
        variable_name = escape_joern_string_literal(params["variable_name"])
        file_scope = params.get("file_pattern", file_filter or ".*")
        if target_method_name:
            method_name = escape_joern_string_literal(target_method_name)
            return f"""
            cpg.method.name("{method_name}")
            .where(_.ast.isIdentifier.name("{variable_name}"))
            .take(3)
            .dumpRaw
            """

        return f"""
        cpg.method
        .where(_.file.name("{file_scope}"))
        .where(_.ast.isIdentifier.name("{variable_name}"))
        .take(5)
        .dumpRaw
        """

    if intent == "check_sanitization":
        # 查过滤/校验逻辑时，优先回到当前可疑方法体本身，
        # 因为真实的长度检查、白名单、认证门禁往往就在进入 sink 之前的局部分支里。
        if target_method_name:
            method_name = escape_joern_string_literal(target_method_name)
            return f"""
            cpg.method.name("{method_name}")
            .take(3)
            .dumpRaw
            """

        # 如果没有方法名，再退回到文件范围内搜索“带防御语义调用”的方法体。
        return f"""
        cpg.method
        .where(_.file.name("{file_filter}"))
        .where(
            _.call.name(
                ".*(encode|escape|sanitize|filter|validate|verify|check|bounds|normalize|canonicalize|auth|authorize|permission|permit|allow|deny|length|size|limit|range|assert|guard|isValid).*"
            )
        )
        .take(5)
        .dumpRaw
        """

    if intent == "trace_forward":
        # UAF/Double-Free 专用：追踪 free 后的代码。
        # 核心思路：查看包含 free 的完整方法体，以及被释放指针在方法内的所有引用。
        if target_method_name and target_variable_name:
            method_name = escape_joern_string_literal(target_method_name)
            variable_name = escape_joern_string_literal(target_variable_name)
            return f"""
            cpg.method.name("{method_name}").take(1).dumpRaw
            """
        if target_method_name:
            method_name = escape_joern_string_literal(target_method_name)
            return f"""
            cpg.method.name("{method_name}").take(1).dumpRaw
            """
        if target_variable_name:
            variable_name = escape_joern_string_literal(target_variable_name)
            return f"""
            cpg.method
            .where(_.file.name("{file_filter}"))
            .where(_.ast.isCall.name(".*free.*"))
            .where(_.ast.isIdentifier.name("{variable_name}"))
            .take(3)
            .dumpRaw
            """
        # 兆底：查找包含 free 的方法体
        return f"""
        cpg.method
        .where(_.file.name("{file_filter}"))
        .where(_.ast.isCall.name(".*free.*"))
        .take(5)
        .dumpRaw
        """

    file_scope = file_filter
    if "upstream_caller_chain" in missing and confidence < 0.5:
        # 当模型明确说“上游链路缺失”且置信度不高时，优先扩大检索范围提升召回率。
        file_scope = ".*"

    # 默认兜底：仍回到 taint flow 查询，保持与主流程输入格式一致（.p 输出）。
    return f"""
    cpg.call
    .where(_.method.file.name("{file_scope}"))
    .reachableByFlows(cpg.parameter)
    .filter(_.elements.size <= {max_len})
    .take(8)
    .p
    """


# 框架名称归一化映射
_LOGIC_FRAMEWORK_MAP = {
    "java": java_logic_queries,
    "spring": java_logic_queries,
    "springboot": java_logic_queries,
    "flask": flask_logic_queries,
    "python": flask_logic_queries,  # 默认 Python 用 Flask 查询
    "django": django_logic_queries,
    "express": express_logic_queries,
    "javascript": express_logic_queries,
    "js": express_logic_queries,
    "node": express_logic_queries,
    "generic": generic_logic_queries,  # 框架无关（SCA 场景用户自写代码）
}


def get_logic_queries(framework: str = "java") -> Dict[str, str]:
    """返回逻辑漏洞专用查询集。

    Args:
        framework: 目标框架名称，支持 java/spring/flask/django/express/js/node 等。
                   不区分大小写。
    """
    key = framework.lower().replace(" ", "").replace("-", "").replace("_", "")
    queries = _LOGIC_FRAMEWORK_MAP.get(key)
    if queries is None:
        # 回退到 java
        queries = java_logic_queries
    return dict(queries)


def get_queries(language: str = "java", variant: str = "generic"):
    """
    根据语言返回对应的查询集。

    Args:
        language: 目标语言，例如 `java`、`cpp`。
        variant: 对 C/C++ 已弃用分支切换；保留参数兼容旧调用，实际始终返回合并包。
                 仅当 ``JOERN_CPP_USE_LEGACY_VENDOR=1`` 时使用窄化的 ``cpp_queries``（mbedtls 路径过滤）。

    Returns:
        对应语言/场景的查询字典。
    """
    if language.lower() in ["c", "cpp", "c++"]:
        if os.environ.get("JOERN_CPP_USE_LEGACY_VENDOR", "0") == "1":
            return cpp_queries
        # 默认：generic 全量内存/通用类 + embedded 固件/协议类（一次扫描全覆盖）
        return dict(cpp_queries_merged)
    return java_queries


# 供静态校验 / Joern 冒烟测试枚举全部查询字典（新增 query 集时请登记）
ALL_LOGIC_QUERY_REGISTRIES: Dict[str, Dict[str, str]] = {
    "java_logic_queries": java_logic_queries,
    "flask_logic_queries": flask_logic_queries,
    "django_logic_queries": django_logic_queries,
    "express_logic_queries": express_logic_queries,
    "generic_logic_queries": generic_logic_queries,
}

ALL_TAINT_QUERY_REGISTRIES: Dict[str, Dict[str, str]] = {
    "java_queries": java_queries,
    "java_reflection_queries": java_reflection_queries,
    "cpp_queries": cpp_queries,
    "cpp_queries_generic": cpp_queries_generic,
    "cpp_queries_embedded": cpp_queries_embedded,
    "cpp_queries_merged": cpp_queries_merged,
    "cpp_auxiliary_queries": cpp_auxiliary_queries,
}