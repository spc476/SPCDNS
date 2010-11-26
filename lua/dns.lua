
show = org.conman.table.show
dns  = require "org.conman.dns"

e = dns.encode {
	id       = 1234,
	query    = true,
	rd       = true,
	opcode   = 'query',
	question = {
		name  = 'yahoo.com.',
		type  = 'mx',
		class = 'in'
	}
}

r,err = dns.query('127.0.0.1',e)

if r == nil then
  print("error:",err)
  os.exit(1)
end

d = dns.decode(r)

for i = 1 , #d.answers do
  print(string.format("%s %d %s %s %d %s",
  			d.answers[i].name,
  			d.answers[i].ttl,
  			d.answers[i].class,
  			d.answers[i].type,
  			d.answers[i].preference,
  			d.answers[i].exchange
  		))
end

