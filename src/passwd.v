module main

import viup
import os
import cbsl
import aeslib
import crypto.bcrypt
import crypto.sha512
import rand
import runtime
import encoding.binary
import json

$if arm64 {
	#flag -L /usr/lib/iup
	#flag -L /lib/gcc/aarch64-linux-gnu/11/
	#flag -L /lib/aarch64-linux-gnu/
	#flag -lgcc
}

const bcrypt_strength = 10
const passwd_file_name = 'passwd.dat'
const template_uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
const template_lowercase = 'abcdefghijklmnopqrstuvwxyz'
const template_number = '0123456789'
const template_symbol = '~!@#$%^&*()_+`-={}[]\\|:;<>,.?/'
const encrypted_item_size = 128 + 4000 + 2

enum FileFormat {
	encrypted_bin
	plain_text
}

@[heap]
struct Passwords {
mut:
	passwd  string
	comment string
}

@[heap]
struct Records {
mut:
	file_format           FileFormat = .encrypted_bin
	master_passwd_hash512 string
	master_passwd_bcrypt  string
	need_save             bool
	items                 []Passwords
	curr_view_items       []int
}

fn create_add_passwd_window() {
	viup.dialog(viup.vbox([
		viup.fill(),
		viup.frame(viup.hbox([
			viup.fill(),
			viup.toggle('uppercase', 'VALUE=On', 'font=Times, Bold 16').set_handle('uppercase'),
			viup.fill(),
			viup.toggle('lowercase', 'VALUE=On', 'font=Times, Bold 16').set_handle('lowercase'),
			viup.fill(),
			viup.toggle('number', 'VALUE=On', 'font=Times, Bold 16').set_handle('number'),
			viup.fill(),
			viup.toggle('symbol', 'VALUE=On', 'font=Times, Bold 16').set_handle('symbol'),
			viup.fill(),
			viup.label('length:', 'ALIGNMENT=ACENTER:ACENTER', 'font=Times, Bold 16'),
			viup.text('VALUE=8', 'font=Times, Bold 16').set_handle('passwd_length'),
			viup.fill(),
			viup.button('Generate', 'font=Times, Bold 16').on_click(generate_passwd),
			viup.fill(),
		]), 'title=Password Settings', 'font=Times, Bold 16'),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.label('Generated Password:', 'font=Times, Bold 16', 'ALIGNMENT=ACENTER:ACENTER'),
			viup.text('', 'size=150', 'expand=No', 'font=Times, Bold 16').set_handle('passwd_edit').on_value_changed(add_passwd_window_ok_button_check),
			viup.fill(),
		]),
		viup.fill(),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.label('Comment:', 'font=Times, Bold 16', 'ALIGNMENT=ACENTER:ACENTER'),
			viup.text('', 'MULTILINE=Yes', 'NC=4000', 'WORDWRAP=Yes', 'size=150x80', 'font=Times, Bold 16').set_handle('comment_edit').on_value_changed(add_passwd_window_ok_button_check),
			viup.fill(),
		]),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.button('Cancel', 'font=Times, Bold 16').on_click(add_passwd_window_cancel),
			viup.fill(),
			viup.button('OK', 'font=Times, Bold 16').set_handle('add_passwd_window_ok_button').on_click(add_passwd_window_ok),
			viup.fill(),
		]),
		viup.fill(),
	]), 'add_passwd_window', 'title=Add Password Item', 'item=-1', 'MARGIN=10x10', 'size=600x250')
}

fn create_main_window() {
	viup.dialog(viup.vbox([
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.label('Search:', 'ALIGNMENT=ACENTER:ACENTER', 'font=Times, Bold 24'),
			viup.text('', 'size=40', 'expand=No', 'font=Times, Bold 24').set_handle('search_edit').on_value_changed(change_search_edit),
			viup.fill(),
		]),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.list('size=110x80', 'font=Times, Bold 20').set_handle('main_list').on_list_item(main_list_item).on_dbl_click(dbl_click_main_list_item),
			viup.text('VALUE=', 'MULTILINE=Yes', 'READONLY=Yes', 'size=160x80', 'font=Times, Bold 20').set_handle('main_list_edit'),
			viup.fill(),
		]),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.button('Settings', 'font=Times, Bold 24').on_click(goto_main_setttings_window),
			viup.fill(),
			viup.button('Add', 'font=Times, Bold 24').on_click(goto_add_passwd_window),
			viup.fill(),
			viup.button('Delete', 'font=Times, Bold 24', 'ACTIVE=No').set_handle('main_window_delete_button').on_click(main_window_delete),
			viup.fill(),
			viup.button('Save', 'font=Times, Bold 24', 'ACTIVE=No').set_handle('main_window_save_button').on_click(main_window_save),
			viup.fill(),
			viup.button('Exit', 'font=Times, Bold 24').on_click(main_window_exit),
			viup.fill(),
		]),
		viup.fill(),
	]), 'main_window', 'title=Password Helper', 'size=600x250', 'EXPAND=Yes', 'MARGIN=10x10')
}

fn create_main_setttings_window() {
	viup.dialog(viup.vbox([
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.label('Old Master Password:', 'font=Times, Bold 16'),
			viup.text('', 'size=100', 'expand=No', 'font=Times, Bold 16').set_handle('old_main_passwd_edit'),
			viup.fill(),
		]),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.label('New Master Password:', 'font=Times, Bold 16'),
			viup.text('', 'size=100', 'expand=No', 'font=Times, Bold 16').set_handle('new_main_passwd_edit'),
			viup.fill(),
		]),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.label('New Password Again:', 'font=Times, Bold 16'),
			viup.text('', 'size=100', 'expand=No', 'font=Times, Bold 16').set_handle('new_main_passwd_edit2'),
			viup.fill(),
		]),
		viup.fill(),
		viup.frame(viup.radio_group(viup.hbox([
			viup.fill(),
			viup.toggle('Encrypted Bin', 'font=Times, Bold 16').set_handle('radio_encrypted_bin'),
			viup.fill(),
			viup.toggle('Plain Text', 'font=Times, Bold 16').set_handle('radio_plain_text'),
			viup.fill(),
		])).set_handle('format_radio'), 'TITLE=File format', 'font=Times, Bold 16'),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.button('Cancel', 'font=Times, Bold 16').on_click(main_setttings_window_cancel),
			viup.fill(),
			viup.button('OK', 'font=Times, Bold 16').on_click(main_setttings_window_ok),
			viup.fill(),
		]),
		viup.fill(),
	]), 'main_setttings_window', 'title=Settings', 'MARGIN=10x10')
}

fn create_main_exit_save_window() {
	viup.dialog(viup.vbox([
		viup.fill(),
		viup.label('Passwords have been changed, save or not ?', 'font=Times, Bold 24'),
		viup.fill(),
		viup.hbox([
			viup.fill(),
			viup.button('Cancel', 'font=Times, Bold 16').on_click(main_exit_save_window_cancel),
			viup.fill(),
			viup.button('Not save', 'font=Times, Bold 16').on_click(main_exit_save_window_not_save),
			viup.fill(),
			viup.button('Save', 'font=Times, Bold 16').on_click(main_exit_save_window_save),
			viup.fill(),
		]),
	]), 'main_exit_save_window', 'title=Please Check!', 'MARGIN=10x10')
}

fn generate_passwd(ih &viup.Control) viup.FuncResult {
	uppercase := if viup.get_handle('uppercase').get_attr('VALUE') == 'ON' { true } else { false }
	lowercase := if viup.get_handle('lowercase').get_attr('VALUE') == 'ON' { true } else { false }
	number := if viup.get_handle('number').get_attr('VALUE') == 'ON' { true } else { false }
	symbol := if viup.get_handle('symbol').get_attr('VALUE') == 'ON' { true } else { false }
	passwd_len := viup.get_handle('passwd_length').get_attr('VALUE').int()

	if passwd_len < 1 || passwd_len > 128 {
		viup.message_error('Password length should between 1~128!')
		return .cont
	}

	mut template := ''
	mut new_passwd := ''
	if uppercase {
		template += template_uppercase
	}
	if lowercase {
		template += template_lowercase
	}
	if number {
		template += template_number
	}
	if symbol {
		template += template_symbol
	}

	for {
		new_passwd = rand.string_from_set(template, passwd_len)
		ok := (!uppercase || new_passwd.contains_any(template_uppercase))
			&& (!lowercase || new_passwd.contains_any(template_lowercase))
			&& (!number || new_passwd.contains_any(template_number))
			&& (!symbol || new_passwd.contains_any(template_symbol))
		if ok {
			break
		}
	}
	viup.get_handle('passwd_edit').set_attr('VALUE', new_passwd)
	xx := viup.clipboard('TEXT=${new_passwd}')
	xx.destroy()

	passwd_text := viup.get_handle('passwd_edit').get_attr('VALUE')
	comment_text := viup.get_handle('comment_edit').get_attr('VALUE')
	if passwd_text.len > 0 && comment_text.len > 0 {
		viup.get_handle('add_passwd_window_ok_button').set_attr('ACTIVE', 'Yes')
	} else {
		viup.get_handle('add_passwd_window_ok_button').set_attr('ACTIVE', 'No')
	}
	return .cont
}

fn main_window_delete(ih &viup.Control) viup.FuncResult {
	list := viup.get_handle('main_list')
	selected_item := list.get_attr('VALUE').int()
	if selected_item == 0 {
		return .cont
	}
	if selected_item > 0 {
		mut records := unsafe { &Records(viup.get_global_reference('records')) }
		item := records.curr_view_items[selected_item - 1]
		records.items.delete(item)
		search_text := viup.get_handle('search_edit').get_attr('VALUE')
		records.update_curr_view_items(search_text)
		sync_curr_view_items_to_list()
		records.need_save = true
		viup.get_handle('main_window_save_button').set_attr('ACTIVE', 'Yes')
	}
	return .cont
}

fn main_window_save(ih &viup.Control) viup.FuncResult {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	if records.save(passwd_file_name) == false {
		viup.message_error('Can\'t save file ${passwd_file_name}')
		return .cont
	}
	records.need_save = false
	ih.set_attr('ACTIVE', 'No')
	return .cont
}

fn main_window_exit(ih &viup.Control) viup.FuncResult {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	if records.need_save {
		viup.get_dialog_handle('main_exit_save_window').show_xy(viup.pos_center, viup.pos_center)
		return .cont
	}
	return .close
}

fn main_exit_save_window_cancel(ih &viup.Control) viup.FuncResult {
	viup.get_dialog_handle('main_exit_save_window').hide()
	return .cont
}

fn main_exit_save_window_not_save(ih &viup.Control) viup.FuncResult {
	return .close
}

fn main_exit_save_window_save(ih &viup.Control) viup.FuncResult {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	if records.save(passwd_file_name) == false {
		viup.message_error('Can\'t save file ${passwd_file_name}')
		return .cont
	}
	return .close
}

fn goto_main_setttings_window(ih &viup.Control) viup.FuncResult {
	// viup.get_handle('main_window').set_attr('ACTIVE','No')
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	match records.file_format {
		.encrypted_bin {
			viup.get_handle('format_radio').set_attr('VALUE', 'radio_encrypted_bin')
		}
		.plain_text {
			viup.get_handle('format_radio').set_attr('VALUE', 'radio_plain_text')
		}
	}
	viup.get_dialog_handle('main_setttings_window').show_xy(viup.pos_center, viup.pos_center)
	return .cont
}

fn goto_add_passwd_window(ih &viup.Control) viup.FuncResult {
	viup.get_handle('passwd_length').set_attr('VALUE', '8')
	viup.get_handle('passwd_edit').set_attr('VALUE', '')
	viup.get_handle('comment_edit').set_attr('VALUE', '')
	viup.get_handle('add_passwd_window_ok_button').set_attr('ACTIVE', 'No')
	viup.get_handle('add_passwd_window').set_attr('TITLE', 'Add Password Item')
	viup.get_handle('add_passwd_window').set_attr('item', '-1')
	viup.get_dialog_handle('add_passwd_window').show_xy(viup.pos_center, viup.pos_center)
	return .cont
}

fn add_passwd_window_ok(ih &viup.Control) viup.FuncResult {
	passwd_text := viup.get_handle('passwd_edit').get_attr('VALUE')
	if passwd_text.len < 1 || passwd_text.len > 128 {
		viup.message_error('Password length should between 1~128!')
		return .cont
	}

	comment_text := viup.get_handle('comment_edit').get_attr('VALUE')
	if comment_text.len < 1 || comment_text.len > 4000 {
		viup.message_error('Comment length should between 1~4000!')
		return .cont
	}

	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	mut record := Passwords{}
	record.passwd = passwd_text
	record.comment = comment_text

	item := viup.get_handle('add_passwd_window').get_attr('item').int()
	if item == -1 {
		records.items << record
	} else {
		records.items[item] = record
	}

	records.need_save = true
	viup.get_handle('main_window_save_button').set_attr('ACTIVE', 'Yes')

	search_text := viup.get_handle('search_edit').get_attr('VALUE')
	records.update_curr_view_items(search_text)
	sync_curr_view_items_to_list()

	viup.get_dialog_handle('add_passwd_window').hide()
	return .cont
}

fn add_passwd_window_cancel(ih &viup.Control) viup.FuncResult {
	viup.get_dialog_handle('add_passwd_window').hide()
	return .cont
}

fn add_passwd_window_ok_button_check(ih &viup.Control) viup.FuncResult {
	passwd_text := viup.get_handle('passwd_edit').get_attr('VALUE')
	comment_text := viup.get_handle('comment_edit').get_attr('VALUE')
	if passwd_text.len > 0 && comment_text.len > 0 {
		viup.get_handle('add_passwd_window_ok_button').set_attr('ACTIVE', 'Yes')
	} else {
		viup.get_handle('add_passwd_window_ok_button').set_attr('ACTIVE', 'No')
	}
	return .cont
}

fn main_setttings_window_ok(ih &viup.Control) viup.FuncResult {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	old_passwd_text := viup.get_handle('old_main_passwd_edit').get_attr('VALUE')
	new_main_passwd := viup.get_handle('new_main_passwd_edit').get_attr('VALUE')
	new_main_passwd2 := viup.get_handle('new_main_passwd_edit2').get_attr('VALUE')

	if old_passwd_text.len > 0 || new_main_passwd.len > 0 || new_main_passwd2.len > 0 {
		hash512 := sha512.hexhash(old_passwd_text)
		mut buffer := string_to_bytes(hash512, 64)

		bcrypt.compare_hash_and_password(buffer, records.master_passwd_bcrypt.bytes()) or {
			viup.message_error('Old password wrong!')
			return .cont
		}

		if new_main_passwd != new_main_passwd2 {
			viup.message_error('New passwords enter difference!')
			return .cont
		}
		set_main_passwd(new_main_passwd)

		records.need_save = true
		viup.get_handle('main_window_save_button').set_attr('ACTIVE', 'Yes')
		viup.message('Hint', 'Main password has been changed!')
	}

	radio_select := viup.get_handle('format_radio').get_attr('VALUE')
	match radio_select {
		'radio_encrypted_bin' {
			if records.file_format != .encrypted_bin {
				records.file_format = .encrypted_bin
				records.need_save = true
				viup.get_handle('main_window_save_button').set_attr('ACTIVE', 'Yes')
			}
		}
		'radio_plain_text' {
			if records.file_format != .plain_text {
				records.file_format = .plain_text
				records.need_save = true
				viup.get_handle('main_window_save_button').set_attr('ACTIVE', 'Yes')
			}
		}
		else {}
	}
	viup.get_dialog_handle('main_setttings_window').hide()
	return .cont
}

fn main_setttings_window_cancel(ih &viup.Control) viup.FuncResult {
	viup.get_dialog_handle('main_setttings_window').hide()
	return .cont
}

fn sync_curr_view_items_to_list() {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	list := viup.get_handle('main_list')
	list.set_attr('REMOVEITEM', 'ALL')

	for i, r in records.curr_view_items {
		comment := records.items[r].comment
		mut display_comment := comment.replace('\n', ' ')
		if display_comment.len > 20 {
			display_comment = display_comment[..20] + '...'
		}
		list.set_attr('${i + 1}', display_comment)
	}
	viup.get_handle('main_list_edit').set_attr('VALUE', '')
	viup.get_handle('main_window_delete_button').set_attr('ACTIVE', 'No')
}

fn change_search_edit(ih &viup.Control) viup.FuncResult {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	search_text := ih.get_attr('VALUE')
	records.update_curr_view_items(search_text)
	sync_curr_view_items_to_list()
	return .cont
}

fn main_list_item(ih &viup.Control, text charptr, item int, state int) viup.FuncResult {
	if state == 0 || item == 0 {
		viup.get_handle('main_window_delete_button').set_attr('ACTIVE', 'No')
		return .cont
	}
	// item was selected
	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	item_selected := records.items[records.curr_view_items[item - 1]]
	comment := item_selected.comment
	viup.get_handle('main_list_edit').set_attr('VALUE', comment)
	passwd := item_selected.passwd
	xx := viup.clipboard('TEXT=${passwd}')
	xx.destroy()
	viup.get_handle('main_window_delete_button').set_attr('ACTIVE', 'Yes')
	return .cont
}

fn dbl_click_main_list_item(ih &viup.Control, item int, text charptr) viup.FuncResult {
	mut records := unsafe { &Records(viup.get_global_reference('records')) }

	the_item := records.items[records.curr_view_items[item - 1]]

	passwd := the_item.passwd
	comment := the_item.comment

	viup.get_handle('main_window_delete_button').set_attr('ACTIVE', 'Yes')

	viup.get_handle('passwd_length').set_attr('VALUE', '${passwd.len}')
	viup.get_handle('passwd_edit').set_attr('VALUE', passwd)
	viup.get_handle('comment_edit').set_attr('VALUE', comment)
	viup.get_handle('add_passwd_window_ok_button').set_attr('ACTIVE', 'Yes')
	viup.get_handle('add_passwd_window').set_attr('item', '${records.curr_view_items[item - 1].str()}')
	viup.get_handle('add_passwd_window').set_attr('TITLE', 'Modify Password Item')
	viup.get_dialog_handle('add_passwd_window').show_xy(viup.pos_center, viup.pos_center)
	return .cont
}

fn generate_bin_item_buffer(passwd string, comment string) []u8 {
	// generate a big buffer to hold the passwd and comment
	assert passwd.len <= 128
	assert comment.len <= 4000
	mut buffer := rand.bytes(encrypted_item_size) or { panic(err) }
	unsafe {
		mut ptr := &u8(buffer.data)
		vmemcpy(&ptr[0], passwd.str, passwd.len)
		vmemcpy(&ptr[129], comment.str, comment.len)
		ptr[passwd.len] = 0
		ptr[129 + comment.len] = 0
	}
	return buffer
}

fn check_password_file_format(filename string) FileFormat {
	contents := os.read_file(filename) or { panic(err) }
	x := json.decode(Records, contents) or { return .encrypted_bin }
	return x.file_format
}

fn (mut records Records) save(filename string) bool {
	match records.file_format {
		.encrypted_bin {
			mut ctx := unsafe { nil }
			ctx = cbsl.cbsl_open(cbsl.CBSL_MODE.cbsl_store_mode, filename)
			if isnil(ctx) {
				return false
			}
			cbsl.cbsl_write(ctx, records.master_passwd_bcrypt.str, u64(records.master_passwd_bcrypt.len))

			hash512 := records.master_passwd_hash512
			mut buffer := string_to_bytes(hash512, 64)

			mut int_tmp := []u8{len: 4}
			binary.little_endian_put_u32(mut int_tmp, u32(records.items.len))
			cbsl.cbsl_write(ctx, int_tmp.data, 4)

			if records.items.len > 0 {
				mut text := []u8{}
				for i in records.items {
					text << generate_bin_item_buffer(i.passwd, i.comment)
				}
				data_out := aeslib.aes_gcm_encrypt(text, buffer[48..64], buffer[36..48])
				binary.little_endian_put_u32(mut int_tmp, u32(data_out.len))
				cbsl.cbsl_write(ctx, int_tmp.data, 4)
				cbsl.cbsl_write(ctx, data_out.data, u64(data_out.len))
			} else {
				binary.little_endian_put_u32(mut int_tmp, u32(0))
				cbsl.cbsl_write(ctx, int_tmp.data, 4)
			}
			cbsl.cbsl_close(ctx)
		}
		.plain_text {
			x := json.encode_pretty(records)
			os.write_file(filename, x) or { panic(err) }
		}
	}
	return true
}

fn (mut records Records) load(filename string) bool {
	match check_password_file_format(filename) {
		.encrypted_bin {
			mut ctx := unsafe { nil }
			ctx = cbsl.cbsl_open(cbsl.CBSL_MODE.cbsl_load_mode, filename)
			if isnil(ctx) {
				return false
			}
			mut master_passwd := ''
			mut u8_string := []u8{len: 61}
			cbsl.cbsl_read(ctx, u8_string.data, 60)
			unsafe {
				master_passwd = tos_clone(&u8(u8_string.data))
			}
			records.master_passwd_bcrypt = master_passwd
			mut int_tmp := []u8{len: 4}
			cbsl.cbsl_read(ctx, int_tmp.data, 4)
			mut len := int(0)
			if runtime.is_big_endian() {
				len = int(binary.big_endian_u32(int_tmp))
			} else {
				len = int(binary.little_endian_u32(int_tmp))
			}

			if len != 0 {
				unsafe { records.items.grow_len(len) }
				cbsl.cbsl_read(ctx, int_tmp.data, 4)
				mut bytes_len := int(0)
				if runtime.is_big_endian() {
					bytes_len = int(binary.big_endian_u32(int_tmp))
				} else {
					bytes_len = int(binary.little_endian_u32(int_tmp))
				}
				mut ciphertext := []u8{len: bytes_len}
				cbsl.cbsl_read(ctx, ciphertext.data, u64(ciphertext.len))
				hash512 := records.master_passwd_hash512
				mut buffer := string_to_bytes(hash512, 64)
				data_out := aeslib.aes_gcm_decrypt(ciphertext, buffer[48..64], buffer[36..48])
				for i, r in records.items {
					unsafe {
						mut ptr := &u8(data_out.data)
						r.passwd = tos_clone(&ptr[i * encrypted_item_size])
						r.comment = tos_clone(&ptr[i * encrypted_item_size + 129])
					}
					records.items[i] = r
				}
			}
			cbsl.cbsl_close(ctx)
			records.file_format = .encrypted_bin
		}
		.plain_text {
			contents := os.read_file(filename) or { return false }
			x := json.decode(Records, contents) or { return false }
			records.master_passwd_hash512 = x.master_passwd_hash512
			records.master_passwd_bcrypt = x.master_passwd_bcrypt
			records.items = x.items.clone()
			records.file_format = .plain_text
		}
	}
	return true
}

fn (mut records Records) update_curr_view_items(keywords string) {
	// 根据keywords更新curr_view_items
	records.curr_view_items.clear()
	if keywords == '' {
		for i in 0 .. records.items.len {
			records.curr_view_items << i
		}
	} else {
		low_keywords := keywords.to_lower()
		for i, r in records.items {
			comment := r.comment
			if comment.to_lower().contains(low_keywords) {
				records.curr_view_items << i
			}
		}
	}
}

fn main() {
	viup.set_global_value('master_passwd_hash512', '')
	viup.set_global_value('master_passwd_bcrypt', '')

	vbox := viup.vbox([
		viup.label('Please enter main password', 'font=Times, Bold 24'),
		viup.text('expand=horizontal', 'value=', 'password=yes', 'font=Times, Bold 24').on_key(input_passwd),
	], 'gap=20', 'margin=10x10', 'expand=yes')
	create_add_passwd_window()
	create_main_window()
	create_main_setttings_window()
	create_main_exit_save_window()

	mut records := Records{}
	viup.set_global_reference('records', &records)

	// if password database does not exist, create first
	if os.exists(passwd_file_name) == false {
		viup.message('Hint', 'File ${passwd_file_name} does not exist!')
	}
	dialog := viup.dialog(vbox, 'MainWindow', 'title=Password Helper', 'size=300x100',
		'resize=no', 'maxbox=no', 'minbox=no', 'menubox=yes').set_handle('passwd_dlg')
	dialog.popup(viup.pos_center, viup.pos_center)

	// if password database does not exist, create first
	if os.exists(passwd_file_name) == false {
		if records.save(passwd_file_name) == false {
			viup.message_error('Can\'t write file ${passwd_file_name}！')
			return
		}
	}

	// open password database, read master password and compare
	if records.load(passwd_file_name) == false {
		viup.message_error('Can\'t read file ${passwd_file_name}！')
		return
	}

	mut buffer := string_to_bytes(records.master_passwd_hash512, 64)
	bcrypt.compare_hash_and_password(buffer, records.master_passwd_bcrypt.bytes()) or {
		viup.message_error('Main password verify fail!')
		return
	}

	records.update_curr_view_items('')
	sync_curr_view_items_to_list()

	viup.get_dialog_handle('main_window').show_xy(viup.pos_center, viup.pos_center)

	viup.main_loop()
}

fn set_main_passwd(passwd string) {
	hash512 := sha512.hexhash(passwd)
	viup.set_global_value('master_passwd_hash512', hash512)
	mut buffer := string_to_bytes(hash512, 64)
	hash2 := bcrypt.generate_from_password(buffer, bcrypt_strength) or { panic(err) }
	viup.set_global_value('master_passwd_bcrypt', hash2)

	mut records := unsafe { &Records(viup.get_global_reference('records')) }
	records.master_passwd_hash512 = hash512
	records.master_passwd_bcrypt = hash2
}

fn input_passwd(ih &viup.Control, c int) viup.FuncResult {
	if c == int(viup.Key.k_enter) {
		val := ih.get_attr('value')
		set_main_passwd(val)

		return .close
	}
	return .cont
}

// string_to_bytes convert '1234' to 0x1234
fn string_to_bytes(the_str string, len int) []u8 {
	assert 2 * len <= the_str.len
	mut buf := []u8{}
	mut c := u8(0)
	for i in 0 .. len {
		c = ('0x' + the_str[2 * i..2 * i + 2]).u8()
		buf << c
	}
	return buf
}
