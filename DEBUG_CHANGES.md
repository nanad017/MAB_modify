# Debug Changes

Tai lieu nay ghi lai cac thay doi da duoc them vao de debug hien tuong tien trinh dung/abort khi chay `run_attack.py`, dac biet quanh nhanh `SP`.

## Muc tieu

- Xac dinh tien trinh dang ket o dau khi log dung tai `pull Arm SP+Rand (2)` / `=== SP ===`.
- Phan biet ro no dang "cho" hay da bi `abort`.
- Neu process chet o muc he thong, co them stack dump de xem thread nao gay ra.

## Cac file da sua

### `run_attack.py`

Da them bat `faulthandler`:

- Tao file log `log/fault.log`.
- Bat dump stack cho tat ca threads.
- Co gang dang ky cac signal sau neu he thong ho tro:
  - `SIGABRT`
  - `SIGSEGV`
  - `SIGBUS`
  - `SIGILL`
  - `SIGFPE`

Tac dung:

- Neu Python process bi abort/segfault o thread nao do, `log/fault.log` se co stack trace de truy vet.

### `arm.py`

Da them log chi tiet trong `ArmSP.transfer()` quanh doan xu ly `SP`:

- Log thong tin truoc khi ghi:
  - `input`
  - `output`
  - `section_idx`
  - `available`
  - `write_offset`
  - `raw_ptr`
  - `virtual_size`
  - `raw_size`
- Log moc:
  - `SP pe.write begin: ...`
  - `SP pe.write done: ...`
  - `SP verify parse begin: ...`
  - `SP verify parse done: ...`

Tac dung:

- Biet process dung truoc `pe.write`, trong `pe.write`, hay sau `pe.write`.

### `sample.py`

Da them log trong `copy_to_scan_folder()`:

- In ra file nao dang duoc copy.
- In ra dich den trong `data/share/rewriter/`.

Tac dung:

- Biet da qua buoc sinh file chua.
- Biet co bi dung o buoc copy sang scan folder hay khong.

### `classifier.py`

Da them log trong `evaluate()`:

- In ra file classifier dang lay ra de cham.

Tac dung:

- Neu process chet o thread classifier thi se co them dau vet de doi chieu.

## Cach xem log sau khi bi dung

Chay lai chuong trinh, neu no dung/chet, xem 3 file sau:

- `log/rewriter.log`
- `log/classifier.log`
- `log/fault.log`

Lenh xem nhanh:

```bash
tail -n 80 log/rewriter.log
tail -n 80 log/classifier.log
tail -n 80 log/fault.log
```

## Dien giai nhanh

- Neu `rewriter.log` co `SP pe.write begin` nhung khong co `SP pe.write done`:
  - Kha nang cao bi dung trong `pe.write(...)`.
- Neu co `SP pe.write done` nhung khong co `copy_to_scan_folder`:
  - Dung sau buoc ghi file, co the o verify parse hoac buoc tiep theo.
- Neu `fault.log` co stack trace:
  - Do la dau moi tot nhat de xac dinh thread va ham gay abort.
- Neu `fault.log` trong:
  - Co the process bi ngat tu ben ngoai, hoac terminal gui tin hieu truoc khi Python kip dump stack.

## Kiem tra da lam

Da kiem tra cu phap cac file da sua bang parse AST.

## Ghi chu

- Cac thay doi nay chi phuc vu debug, khong thay doi logic tan cong chinh.
- Khi tim ra nguyen nhan goc, co the bo cac log nay di de tranh loang log.
