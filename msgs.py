#
# Message services: formatting a message based on information from a
# hinfo object and the class, and some standard messages.

# Format messages by stirring them with a dictionary of information for use
# in Python-style format strings. The dictionary is drawn from hostinfo and
# class data.
def format(msg, hi, cls, sdict = None, **kwargs):
	d = hi.getinfo()
	if cls != None:
		d['class'] = cls.clsname
		d['lineno'] = cls.lineno
		if cls.label:
			d['label'] = cls.label.replace("_", " ")
	if kwargs:
		d.update(kwargs)
	# Give the user some way to insert \r, \n, and \r\n.
	d['cr'] = "\r"; d['nl'] = "\n"; d['eol'] = "\r\n"
	# We cannot mutate sdict, so we use a new dictionary (rd, the
	# root dictionary) to get the semantics we want, which is that
	# sdict cannot override values from elsewhere if they exist.
	# (This means we put sdict in first, then d in later.)
	rd = {}
	if sdict:
		rd.update(sdict)
	rd.update(d)
	return msg % rd


# Standard messages.
logconnect = "accepted: %(connsum)s by %(class)s"
loglimits = "refused: %(connsum)s rejected by %(class)s %(limit)s limit"
logreject = "rejected: %(connsum)s by %(class)s"
rejmsgs = { 'reject': logreject,
	   'ipmax': loglimits,
	   'connmax': loglimits,
	   }
