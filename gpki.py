#!/usr/local/bin/python3
import gnupg
import logging
import os
import shutil
import subprocess
import tempfile

from collections import namedtuple
from datetime import datetime
from getpass import getpass
from iterfzf import iterfzf
from pathlib import Path
from typing import NewType


verbose=True

ShellCommand = NewType("ShellCommand", str)


Request = namedtuple('Request', ["branch", "title"])
FileChange = namedtuple('FileChange', ["op", "path"])
KeyChange = namedtuple('KeyChange', ["added", "removed"])
Key = namedtuple('Key', ["name", "email", "description", "fingerprint", "created_on", "expires_on"])

def shell(cwd, command: ShellCommand) -> str:
    logging.debug(command)
    proc = subprocess.run(command, cwd=cwd, shell=True, capture_output=True)
    if proc.returncode == 0:
        return proc.stdout.decode("utf-8")
    else:
        raise EnvironmentError(f"The command [{command}]\nfailed with return code {proc.returncode}.\nstderr:\n{proc.stderr.decode('utf-8')}")



class GPG(object):
	def __init__(self, gnupghome):
		super(GPG, self).__init__()
		self.gpg = gnupg.GPG(gnupghome = gnupghome, options=['--yes', '--pinentry-mode','loopback'], verbose = verbose)
		self.gpg.encoding = 'utf-8'
		
	def generate_key(self, name, email, description):
		# TODO handle null email and description
		key_spec = f"""
				   Key-Type:	RSA
				   Key-Length: 	3072
				   Name-Real: 	{name}
				   Name-Email: 	{email}
				   Name-Comment:{description}
				   Expire-Date:	6m
				   Passphrase: 	{getpass("New key passphrase: ")}
				   """

		return self.gpg.gen_key(key_spec).fingerprint.lower()

	def export_public_key(self, name):
		return self.gpg.export_keys(name)

	def import_public_key(self, armored):
		print(f"Importing {armored}")
		return self.gpg.import_keys(armored).results

	def private_keys_list(self):
		keys = self.gpg.list_keys(True)
		return map(self.parse_key, keys)

	def private_key_fingerprint(self, name):
		keys = self.gpg.list_keys(True, keys = name)
		return keys[0]["fingerprint"].lower() if keys else None

	def public_keys_list(self, names = None):
		keys = self.gpg.list_keys(False, keys = names)
		return map(self.parse_key, keys)

	def public_key_name(self, fingerprint):
		keys = self.gpg.list_keys(False, keys = fingerprint)
		return keys[0]["uids"][0] if keys else None

	def public_key_fingerprint(self, name):
		keys = self.gpg.list_keys(False, keys = name)
		return keys[0]["fingerprint"].lower() if keys else None

	def file_key_fingerprint(self, path):
		keys = self.gpg.scan_keys(keys = name)
		return keys[0]["fingerprint"] if keys else None

	def remove_private_key(self, fingerprint, passphrase):
		self.gpg.delete_keys(fingerprint, True, passphrase = passphrase)
		
	def remove_public_key(self, fingerprint):
		self.gpg.delete_keys(fingerprint, False)

	def encrypt(self, recipient, signatory, source, target, passphrase):
		if source is None:
			data = []
			print("Write message, then press enter and ctrl+d")
			for line in sys.stdin:
				data.append(line)
			result = self.gpg.encrypt("".join(data), recipient, sign = signatory, output = target, passphrase = passphrase)
		else:
			with open(source, "rb") as data:
				result = self.gpg.encrypt_file(data, recipient, sign = signatory, output = target, passphrase = passphrase)
		
		if not result.ok:
			print(f"Could not encrypt: {result.status}. Was passphrase correct?")
			return
		if target is None: print(result)
		
	def decrypt(self, source, target):
		if source is None:
			data = []
			print("Paste message, then press enter and ctrl+d")
			for line in sys.stdin:
				data.append(line)
			result = self.gpg.decrypt("".join(data), output = target)
		else:
			with open(source, "rb") as data:
				result = self.gpg.decrypt_file(data, output = target)
		if not result.ok:
			print(f"Could not decrypt: {result.status}. Was passphrase correct?")
			return
		if target is None: print(result)

	def scan(self, file):
		keys = self.gpg.scan_keys(file)
		return map(self.parse_key, keys)

	def parse_key(self, raw_key):
		uid = raw_key["uids"][0]
		name = uid[0]
		email = uid[1][1:-1]
		description = uid[2][1:-1]
		fingerprint = raw_key["fingerprint"].lower()
		created_on = self.key_parse_date(raw_key, "date")
		expires_on = self.key_parse_date(raw_key, "expires")
		return Key(name, email, description, fingerprint, created_on, expires_on)

	def __key_parse_date(self, key, field):
		return datetime.fromtimestamp(int(key[field])).strftime("%Y-%m-%d")

class KeyChangeListener(object):
	def __init__(self, gpg):
		super(KeyChangeListener, self).__init__()
		self.__gpg = gpg
		
	def key_added(self, path):
		print(f"A {path}")
		self.__gpg.import_public_key(path)

	def key_updated(self, path):
		print(f"M {path}")
		self.__gpg.import_public_key(path)

	def key_removed(self, path):
		print(f"R {path}")
		fingerprint=self.__gpg.file_key_fingerprint(path)
		self.__gpg.remove_public_key(fingerprint)

class Git(object):
	def __init__(self, home):
		super(Git, self).__init__()

		self.home = home
		self.identity_dir = f"{home}/identities"
		self.key_dir = f"{home}/keys"
	
	def update(self, listener) -> list:
		from pathlib import Path
		if Path(f"{self.home}/.git").is_dir():
			# TODO reenable
			# branch=shell(self.home, "git rev-parse --abbrev-ref HEAD")
			# old_hash=shell(self.home, "git rev-parse HEAD")
			# shell(self.home, f"git pull origin {branch}")
			# new_hash=shell(self.home, "git rev-parse HEAD")
			
			# if old_hash != new_hash:
			# 	raw_output = shell(self.home, f'git diff --name-status "{old_hash}".."{new_hash}" | sort')
			# 	for line in filter(None, raw_output.split("\n")):
			# 		op, path = line.split('\t')
			# 		if 	 op == 'A': listener.key_added(path)
			# 		elif op == 'M': listener.key_updated(path)
			# 		elif op == 'R': listener.key_removed(path)
			pass
		else:
			from os import listdir
			
			repo = input("Specify git repository: ")
			shell(self.home, f"git clone {repo} {self.home}")
			mkdir(self.identity_dir)
			mkdir(self.key_dir)

			print(self.identity_dir)
			for path in listdir(self.identity_dir):
				listener.key_added(path)

			for path in listdir(self.key_dir):
				listener.key_added(path)

	def push(self, branch, message):
		# TODO recover on failure!
		shell(self.home, f"git checkout -b {branch}")
		shell(self.home, f"git add -A")
		shell(self.home, f"git commit -m '{message}'")
		shell(self.home, f"git push origin {branch}")
		shell(self.home, f"git checkout -")
		shell(self.home, f"git branch -D {branch}")

	def list_unmerged_branches(self):
		branch = self.__current_branch()
		raw    = shell(self.home, f"git branch -a --no-merged origin/{branch}").splitlines()
		strip    = lambda line: line.strip()
		to_tuple = lambda branch: Request(branch, self.__commit_title(branch))
		return map(to_tuple, map(strip, raw))

	def file_diff(self, branch):
		raw 	 = shell(self.home, f'git diff --name-status HEAD.."{branch}" | sort').splitlines()
		strip    = lambda line: line.split("\t")
		to_tuple = lambda segments: FileChange(segments[0], segments[1])
		return map(to_tuple, map(strip, raw))

	def open_worktree(self, dir, branch):
		path = Path(f"{dir}/{branch}")
		x = shell(self.home, f"git worktree add {path} {branch}")
		return Git(path)

	def close_worktree(self, branch):
		shell(self.home, f"git worktree remove {branch}")

	def __current_branch(self):
		return shell(self.home, "git rev-parse --abbrev-ref HEAD")

	def __commit_title(self, ref):
		return shell(self.home, f"git log -1 --format=%s {ref}").strip()

	def __update_repository(self):
		pass

	def path_to(self, path):
		return Path(f"{self.home}/{path}")


def mkdir(name, mode = None):
	if mode is None: 
		os.makedirs(name, exist_ok = True)
	else:
		os.makedirs(name, mode, exist_ok = True)
	return name


class GPKI(object):
	def __init__(self, home):
		super(GPKI, self).__init__()
		self.__file_gpghome 	= mkdir(f"{home}/vault/private", 0o700)
		self.__file_repository 	= mkdir(f"{home}/vault/public")
		self.__review_dir		= mkdir(f"{home}/reviews")
		self.__gpg = GPG(self.__file_gpghome)
		self.__git = Git(self.__file_repository)

		listener = KeyChangeListener(self.__gpg)
		self.__git.update(listener)

	def generate_identity(self, name, email, description):
		# TODO verify that repository is in clean state?
		existing_key = self.__gpg.private_key_fingerprint(name)
		if existing_key is not None:
			# If key exists, confirm removal of the private varsion and move public one to the archive
			response = input(f"Replace existing identity of {existing_key}? [yN] ")
			if response.lower() != "y" : return
			passphrase = getpass(f"Specify passphrase for the existing key of [{name}]: ")
			self.__gpg.remove_private_key(existing_key, passphrase)
			# TODO what with public key? I think we should keep it until revoked / expired
			#  maybe asking if it should be revoked also?

		fingerprint = self.__gpg.generate_key(name, email, description)
		if fingerprint is None: return
		
		key = self.__gpg.export_public_key(name)
		file = Path(f"{self.__git.identity_dir}/{name}/${fingerprint}")
		self.__export_key(key, Path(file))
		# TODO is it a good branch name? It allows multiple choices for someone to choose from
		#   but also allows for semi-automated verification, approval and rejection
		self.__git.push(f"{name}/{fingerprint}", f"Publish key {name}/{fingerprint}")
		print(key)
		# TODO maybe find a way to revert changes if PR gets rejected ?

	def list_signatories(self):
		print("fingerprint                              created-on expires-on\tidentity\temail\tdescription")
		for key in self.__gpg.private_keys_list():
			# TODO no idea how to align those nicely
			print(f"{key}")

	def list_recipients(self):
		print("fingerprint                              created-on expires-on\tidentity\temail\tdescription")
		for key in self.__gpg.public_keys_list():
			# TODO no idea how to align those nicely
			print(f"{key}")

	def encrypt(self, source, target):
		f = lambda key: f"{key.fingerprint} {key.created_on} {key.expires_on} {key.name} {key.email} {key.description}"
		available_recipients = map(f, self.__gpg.public_keys_list())
		selection = iterfzf(available_recipients, prompt = "Select recipient: ")
		if selection is None: return
		recipient = selection.split()[0]
		
		available_signatories = map(f, self.__gpg.private_keys_list())
		selection = iterfzf(available_signatories, prompt = "Select signatory or press ctrl+d to not sign ")
		signatory = None if selection is None else selection.split()[0]

		passphrase = getpass(f"Specify passphrase for [{selection[0]}]: ")

		self.__gpg.encrypt(recipient, signatory, source, target, passphrase)

	def decrypt(self, source, target):
		self.__gpg.decrypt(source, target)

	def import_keys(self, files):
		if files == []:
			print("Paste the key and then press ctrl+d on an empty line")
			data = read_multiline_string()
			file = tempfile.mkstemp()[1]
			
			with open(file, "w") as output:
				output.write(data)
			files = [file]
		
		imported = False
		for file in files:
			for fingerprint in self.__import_key(file):
				name = self.__gpg.public_key_name(fingerprint)
				file = f"{self.__git.identity_dir}/{name}/{fingerprint}"
				key = self.__gpg.export_public_key(fingerprint)
				__export_key(key, Path(file))
				imported = True

		if not imported: return
		branch = input("Specify branch name: ").replace(" ", "_")
		message = input("Specify commit title: ")
		self.__git.push(branch, message)
	
	def export_keys(self, names):
		for name in names:
			key = self.__gpg.export_public_key(name)
			if key == "":
				print(f"{name}: Failed\n")
			else:
				print(f"{name}:\n{key}\n")

	def __export_key(self, key, path):
		mkdir(path.parent)
		with open(path, "w") as file:
			file.write(key)

	def __import_key(self, path):
		keys = self.__gpg.scan(path)
		print(f"File {path} contains:")
		for key in keys:
			print(f"{key.fingerprint} key of {key.name} valid between {key.created_on} and {key.expires_on}") # TODO we should treat importing single file a'la transcation
		if input("is that OK? [yN] ").lower() != 'y': return []

		with open(path, "rb") as file:
			imported = self.__gpg.import_public_key(file.read())
		
		if imported == []: return []
		mkdir(f"{self.__git.identity_dir}") # I don't really want to repeat that every goddamn time...
		for status in imported:
			fingerprint = status["fingerprint"].lower()
			reason = status["text"]
			if status["ok"] is None:
				print(f"Failed to import {fingerprint} due to: {reason}")
			else: # TODO can special-case unchanged keys (e.g. don't print or print "Unchanged {fingerprint}" ?)
				print(f"Imported: {fingerprint}. {reason}")

		# TODO should probably not return fingerprints of the unchanged keys
		return map(lambda x: x["fingerprint"].lower(), imported)

	def review_requests(self):
		unmerged = list(self.__git.list_unmerged_branches())
		if unmerged == []: return
		for i, request in enumerate(unmerged): 
			print(f"{i}) {request.title}")

		selected = int(input(f"Select request to review (0-{len(unmerged)}): "))
		request = unmerged[selected] # TODO more checks

		print("Requested changes:")
		changes  = self.__git.file_diff(request.branch)
		reviewed = self.__git.open_worktree(self.__review_dir, request.branch)
		try:
			def map_change(change):
				if change.op == 'A':
					path = reviewed.path_to(change.path)
					return KeyChange(added = list(self.__gpg.scan(path)), removed = [])
				if change.op == 'R':
					path = __git.path_to(change.path)
					return KeyChange(added = [], removed = list(self.__gpg.scan(path)))
				if change.op == 'M':
					removed = __git.path_to(change.path)
					added = reviewed.path_to(change.path)
					return KeyChange(added, removed)
				# TODO also compare file name with its fingerprint
			for x in map(map_change, changes):
				print(x)
			# TODO decide: accept / review (also confirm)
		finally:
			self.__git.close_worktree(request.branch)
	

def cmd_identity_generate(gpki, args):
	name = args[0] if args else input("Specify name (required): ")
	email = input("Specify email (optional): ")
	descr = input("Specify description (optional): ")
	gpki.generate_identity(name, email, descr)

def cmd_encrypt(gpki, args):
	if len(args) == 0: 
		gpki.encrypt(None, None)
	elif len(args) == 1:
		path = Path(args[0])
		if path.is_file():
			gpki.encrypt(source = path, target = None)
		else:
			gpki.encrypt(source = None, target = path)
	else:
		source = Path(args[0])
		target = Path(args[1])
		if not source.is_file():
			raise Exception(f"Not a file: {source}")
		if target.is_file():
			pass # TODO ask to overwrite
		gpki.encrypt(source, target)

def dispatch(gpki, args, routes):
	route = routes[args[0]]
	if type(route) is dict:
		dispatch(gpki, args[1:], route)
	elif callable(route):
		route(gpki, args[1:])
	else:
		raise Error(f"Unsupported route: {route}")

def read_multiline_string(prompt = None):
	if prompt is not None:
		print(prompt)
	lines = []
	for line in sys.stdin:
		lines.append(line)
	return "".join(lines)


routes = {
	"decrypt" 	: lambda gpki, args: gpki.decrypt(None, None),
	"encrypt" 	: cmd_encrypt,
	"new"		: cmd_identity_generate,
	"key" 	  	: {
		"import": lambda gpki, files: gpki.import_keys(files),
		"export": lambda gpki, names: gpki.export_keys(names)
	},
	"recipient"	: {
		"list"  : lambda gpki, args: gpki.list_recipients()
	},
	"request"	: {
		"review": lambda gpki, args: gpki.review_requests()
	},
	"signatory" : {
		"list"	: lambda gpki, args: gpki.list_signatories()
	}
}

def main(args):
	gpki = GPKI("/tmp/foobarbaz")
	dispatch(gpki, args, routes)
import sys
args = sys.argv[1:]
verbose=True
main(args)

# gpki =  GPKI("/tmp/foobar") 
# gpki.generate_identity("maza", "email@domain", "foobar")






