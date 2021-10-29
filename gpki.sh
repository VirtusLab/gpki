#!/bin/sh

_HOME=${GPKI_HOME:-${HOME}/.config/gpki}
VAULT=${_HOME}/vault/private
REPO=${_HOME}/vault/public
KEYS=${REPO}/keys
IDS=${REPO}/identities
SELF_IDENTITY=${_HOME}/identity
DISPATCH="$(pwd)/$(basename $0)" # TODO use actual location from _HOME

gpg(){
	command gpg --homedir "$VAULT" "$@"
}

identity(){
	command=$1; shift
	case $command in
		generate) identity_generate "$@";;
			list) identity_list "$@";;
			show) identity_show "$@";;
			  '') identity_select_and_show;;
			   *) identity_show "$command" "$@";;
	esac
}

identity_generate(){
	# TODO confirm empty passphrase
	_identity_setup \
	&& _revoke_existing_identity "${identity}" \
	&& read -s -p "Passphrase: " passphrase \
	&& _gpg_generate_keypair "$identity" "$passphrase" \
	&& hash=$(_gpg_fingerprint_of "${identity}") \
	&& _gpg_export_public_key "${identity}" "${KEYS}/${hash}" \
	&& echo "${hash}" > "${IDS}/${identity}" \
	&& _repo_publish "$identity" "Updated identity of ${identity}"
	# TODO 0: limit noise from this function (git / gpg stderr)
	# TODO 1: notify the user that recipients won't be able to decrypt the message until branch get's merged
	# TODO 2: reset git repo and self identity if failed at any point
	# users are immediatelly be able to use the new key to encrypt the data, while the update to repo is still pending
	# TODO we need ability to reset our identity to the one from the repo if PR gets rejected
}

_gpg_export_public_key(){
	identity=$1
	file=$2
	gpg --armor --export "${identity}" > "${file}"
}

_gpg_fingerprint_of(){
	name=$1
	# takes fingerprint, which is stored in the 10th field of a ':' separated list starting with "fpr" string
	# it might return many lines but only the first one interests us (as it is for the public key)
	gpg --with-colons --fingerprint "$name" | grep "fpr" | cut -d':' -f10 | sed -n '1p'
}

_repository_push()(
	branch=$(uuidgen)
	cd "$REPO" && git checkout --branch "${branch}" \
	&& git add -A && git push origin "${branch}" \
	&& git checkout master
)

identity_select_and_show(){
	identity_list | fzf -i | identity_show
}

identity_show(){
	name=$1
	gpg --armor --export "${name}"
}

identity_synchronize(){
	_identity_setup \
	&& installed_version=$(_gpg_fingerprint_of "${identity}") \
	&& latest_version=$(cat "${IDS}/${identity}") \
	&& ([ "$installed_version" = "$latest_version" ] \
		|| _repo_updated_file "${IDS}/${identity}" \
		|| (echo "Failed to synchronize identity ${identity}" && exit 1))
}

_identity_setup(){
	if [ -e "${SELF_IDENTITY}" ]; then
		identity=$(cat "$SELF_IDENTITY")
	else
		read -p "Set your identity: " identity
		[ -z "${identity}" ] && exit 1
		echo "${identity}" > "${SELF_IDENTITY}"
	fi
}

identity_list(){
	command ls "$IDS" # user might have an alias for ls, so let's go with command
}

gpg_list_signatory(){
	gpg --with-colons --list-secret-keys | grep uid | cut -d':' -f10 | sort | uniq
}

repository(){
	command=$1; shift
	case $command in
		status) repository_status "$@";;
	esac
}

repository_status()(
	cd "$REPO" && git status --short
)

repository_refresh()(
	cd "$REPO"
	old=$(git rev-parse HEAD)
	git pull origin master > /dev/null || exit 1
	new=$(git rev-parse HEAD)
	git diff --name-status "${old}".."${new}" | sort | xargs -P1 -n2 -- "${DISPATCH}" _repo_refresh_file
)

_latest_key_of(){
	identity=$1
	cat "${IDS}/${identity}"
}

identity_revoke(){
	# TODO 1: condirm revocation
	# TODO 2: how to handle revoked keys? For now, let's keep them in repo if someone wants to decrypt old message manually
	_identity_setup \
	&& hash=$(_latest_key_of) \
	&& _gpg_remove_identity "${identity}" \
	&& _repo_remove_identity "${identity}" \
	&& _repo_publish "${identity}" "Revoked identity of ${identity}"
}

encrypt(){
	passphrase=$1
	if [ -z "$passphrase" ]; then
		echo "No passphrase" # TODO ask for confirmation
	fi
	recipient=$(identity_list | fzf -i)
	[ -z "${recipient}" ] && exit 1
	recipient_key="$(cat ${IDS}/${recipient})"
	# TODO ensure installed key hash is the same as latest hash of both self and recipient
	gpg --encrypt --sign --armor -r "${recipient_key}"
}

decrypt(){
	echo "Enter encrypted message, then press ctrl+d"
	gpg --decrypt
}

_repo_refresh_file(){
	op=$1
	name=$2
	echo "$op $name"
	case $op in
		A) _repo_added_file   "$name";;
		R) _repo_removed_file "$name";;
		M) _repo_updated_file "$name";;
		*) echo "Unknown repository change $op $name" && exit 1;; # TODO handle e.g. moves which would be basically renames?
	esac
}

_repo_added_file(){
	file="${REPO}/$1"
	case $file in
		$IDS/*) #file name format: name/latest
		name="$(basename $file)"
		hash="$(cat $file)"
		
		_gpg_contains_public "${hash}" || (_gpg_import_public_key "${hash}" && echo "A $name")
		;;
	esac
}

_gpg_contains_public(){
	ref="$1"
	gpg --list-keys "${ref}" > /dev/null 2>&1
}

_gpg_contains_private(){
	ref="$1"
	gpg --list-secret-keys "${ref}" > /dev/null 2>&1
}

_gpg_import_public_key(){
	hash=$1
	trust_level=6 # trust ultimately
	_gpg_contains_public "${hash}" \
	|| (gpg --import "${KEYS}/${hash}" && echo "${hash}:${trust_level}:" | gpg --import-ownertrust) > /dev/null 2>&1
}

_repo_removed_file(){
	file="${REPO}/$1"
	name=$(basename $file)
	case $file in
		 $IDS/*) _gpg_remove_private_key "$(cat $file)"	&& echo "R identity ${name}";;
		# If key was removed, it means it got compromised
		$KEYS/*) _gpg_remove_public_key  "${name}" 		&& echo "R key ${name}";;
	esac
}

_repo_updated_file(){
	file="${REPO}/$1"
	name=$(basename $file)
	case $file in
		 $IDS/*) _gpg_import_public_key "$(cat $file)" && echo "U identity ${name}";;
		$KEYS/*) echo "F key modified: ${file}";; # TODO keys should NEVER change. should we revoke it now or restore?
	esac
}

# This will fail if there already is an update to this repo pending
# TODO what to do if there is already an update pending?
_repo_publish()(
	name=$1
	message=$2
	branch="$name/update-identity"
	cd "${REPO}" \
	&& git checkout -b "${branch}" \
	&& git add -A \
	&& git commit -m "Updated ${name}" \
	&& git push origin "${branch}" \
	&& git checkout - \
	&& git branch -D "${branch}"
)

_gpg_generate_keypair(){
	name=$1
	passphrase=$2
	if [ -z "$passphrase" ]; then
		gpg --quick-generate-key "$name" default default 6m
	else
		gpg --batch --pinentry-mode=loopback --passphrase="$passphrase" --quick-generate-key "$name" default default 6m	
	fi
}

_gpg_remove_identity(){
	# first we need to remove private key
	fingerprint=$(cat "${IDS}/${identity}")
	(_gpg_remove_private_key "${fingerprint}" && _gpg_remove_public_key "${fingerprint}")  # TODO what if something failed?
}

_gpg_remove_private_key(){
	fingerprint=$1
	if gpg --list-secret-keys "${fingerprint}"; then
		gpg --batch --yes --delete-secret-key "${fingerprint}"
	fi
}

_gpg_remove_public_key(){
	fingerprint=$1
	if gpg --list-keys "${fingerprint}"; then
		gpg --batch --yes --delete-key "${fingerprint}"
	fi
}

#TODO find better name. It confirms revocation of an existing identity
_revoke_existing_identity(){
	if gpg --list-keys "${identity}" >/dev/null 2&>1 ;then
		read -p "Revoke existing identity of $identity? [yN] " yn
		response=$(echo ${yn} | tr '[:upper:]' '[:lower:]')
		([ "${response}" = "y" ] || [ "${response}" = "yes" ]) && _gpg_remove_identity "${identity}"
	fi
}

_refresh_repository(){
	if [ -e "${REPO}" ]; then
		repository_refresh
	else
		read -p "Specify git repository: " repository
		[ -z "$repository" ] && exit 1
		mkdir -p "$_HOME" && git clone "${repository}" "${REPO}" > /dev/null 2>&1 || (echo "Failed to clone $repository" && exit 1)
		[ -d "$KEYS" ] || mkdir "$KEYS" 
		[ -d "$IDS" ] || mkdir "$IDS" 

		for file in $(cd "${REPO}" && git ls-tree --full-tree -r --name-only HEAD); do
			_repo_added_file "${file}" || (echo "Failed to import $file" && exit 1)
		done
		echo # new line for cleaner CLI interface
	fi	
}

_initialize_vault(){
	[ -e "${VAULT}" ] || mkdir -p -m 700 "${VAULT}"
}

case $1 in
	_*)"$@";; # internal invocation, don't auto-refresh
	 *)_initialize_vault && _refresh_repository && "$@";;
esac


###### Test:
# 1. multiple users (auto-updating the repo)


