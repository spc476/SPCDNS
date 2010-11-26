
require "org.conman.dns"
require "org.conman.table"

local SERVER = "127.0.0.1"

local dns    = org.conman.dns
local show   = org.conman.table.show

-- **************************************************************

local function query(host,type)
  local e = dns.encode {
  		id = math.random(),
  		query = true,
  		rd    = true,
  		opcode = 'query',
  		question = {
  			name = host,
  			type = type,
  			class = 'in'
  		}
  	}
  	
  local r,err = dns.query('127.0.0.1',e)
  
  if r == nil then
    print("error:",err)
    return nil
  end
  
  return dns.decode(r)
end

-- ****************************************************************

local function query_a(host)
  local a,err = query(host,'a')
  
  if a == nil then
    print("error:",err)
    return nil
  end
  
  return a.answers[1]
end

-- ****************************************************************

local function query_mx(host)
  local mx,err = query(host,'mx')
  
  if mx == nil then
    print("error:",err)
    return nil
  end
  
  table.sort(mx.answers,function(a,b) return a.preference < b.preference end)
  
  for i = 1 , #mx.answers do
    mx.answers[i].ADDRESS = mx.additional[mx.answers[i].exchange]
    if mx.answers[i].ADDRESS == nil then
      mx.answers[i].ADDRESS = query_a(mx.answers[i].exchange)
    end
  end
  
  return mx.answers
end

-- **************************************************************

if #arg == 0 then
  io.stderr:write(string.format("usage: %s domain\n",arg[0]))
  os.exit(1)
end

local results = query_mx(arg[1])

for i = 1 , #results do
  local mx,ip
  
  mx = results[i].exchange
  
  if results[i].ADDRESS.ip then
    ip = results[i].ADDRESS.ip
  else
    ip = results[i].ADDRESS.ipv6
  end
  
  if ip == nil then
    ip = "(none)"
  end
  
  print(mx,ip)
end
