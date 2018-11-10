project('pktfwdbr', 'c')

mosquittomainloop = subproject('mosquittomainloop')

src = ['pktfwdbr.c']
deps = [ dependency('glib-2.0'),
         dependency('json-glib-1.0'), 
         mosquittomainloop.get_variable('mosquittomainloop_dep')]

executable('pktfwdbr', src, 
           dependencies : deps, 
           install : true,
           install_dir : 'sbin')