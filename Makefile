update:
	git pull
	git add -A 
	git commit -m "Automatic uploading. No comments!" || true
	git push
configure:
	git config credential.helper store
	git config --global user.email xinshengzzy@gmail.com
	git config --global user.name xinshengzzy
