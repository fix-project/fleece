macro (add_exec name)
	add_executable ("${name}" "${name}.cc")
	target_link_libraries ("${name}" aws http util ${SSL_LDFLAGS} ${SSL_LDFLAGS_OTHER})
endmacro (add_exec)

add_exec(yay)
add_exec(accountsettings)
