/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//Decompile the function at the cursor and its callees, then output facts files corresponding to the pcodes
//@category PCode

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class PCodeDumpSF extends GhidraScript {
	
	String SEP = ":";
	String TAB = "\t";
	String QUOTE = "\"";
	
	Set<Function> toProcess = new HashSet<Function>();
        Set<Function> isEP = new HashSet<Function>();
	File outputDirectory;
	PrintWriter ia;
	//HashMap<String, PrintWriter> pws = new HashMap<String, PrintWriter>();
	HashSet<String> decls = new HashSet<String>();
	HashMap<String, String> pairs;
	HashSet<String> types = new HashSet<String>();
	HashMap<HighVariable,VarnodeAST> extraGlobals = new HashMap<HighVariable,VarnodeAST>();
	
	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		outputDirectory = askDirectory("Select Directory for Results", "OK");
		try {
			File f = new File(outputDirectory,currentProgram.getName()+".facts");
			ia = new PrintWriter(f);
			//pws.put("input_assist.dl", ia);
			//ia.println("table S2N[string, int]");
			//File f2 = new File(outputDirectory, "S2N.facts");
			//PrintWriter pw = new PrintWriter(f2);
			//pws.put("S2N", pw);
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.setSimplificationStyle("decompile");
		
		if (!ifc.openProgram(this.currentProgram)) {
			throw new DecompileException("Decompiler", "Unable to initialize: "+ifc.getLastMessage());
		}
		
		toProcess = new HashSet<Function>();
		Function func = this.getFunctionContaining(this.currentAddress);
		if (func != null) {
			collectFunctions(func);
			isEP.add(func);
		} else {
			for (Function f : this.currentProgram.getFunctionManager().getFunctions(true)) {
				collectFunctions(f);
				isEP.add(f);
			}
			for (Function f : this.currentProgram.getFunctionManager().getExternalFunctions()) {
				collectFunctions(f);
			}
		}
		for (Function f : toProcess) {
			processFunction(ifc, f);
			if (monitor.isCancelled()) break;
		}
		
		closeFiles();
	}

	private void collectFunctions(Function f) {
		if (toProcess.contains(f)) return;
		toProcess.add(f);		
		Set<Function> calledFunctions = f.getCalledFunctions(monitor);
		for (Function function : calledFunctions) {
			collectFunctions(function);
		}	
	}
	
	protected void processFunction(DecompInterface ifc, Function f) {
		pairs = new HashMap<String, String>();
		System.out.println("processing "+f.getName()+SEP+f.getEntryPoint());

		SymbolIterator externalSymbols = f.getProgram().getSymbolTable().getSymbols(f.getName());
		while (externalSymbols.hasNext()) {
		    Symbol next = externalSymbols.next();
		    if (!next.isExternal()) {
			Address address = next.getAddress();
			export("HFUNC_LOCAL_EP", f.getEntryPoint().toString(), address.toString());
		    }
		}
		HighFunction high = getHighFunction(ifc, f);
		if (high == null) {
			String id = funcID(f);
			export("HFUNC_FUNC",	id, id);
			export("HFUNC_TOSTR",	id, id);
			export("HFUNC_PROTO",	id, id);
			export("HFUNC_EP",		id, f.getEntryPoint().toString());
			export("HFUNC_ISEXT",	id, "true");
			return;
		}
		
		HashSet<PcodeOp> set = new HashSet<PcodeOp>();
		Iterator<PcodeOpAST> opiter = high.getPcodeOps();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			if (op != null) {
				set.add(op);
				exportPcode(high, op);
			}
		}
		exportPcodeOpSequence(high, set);
		exportHighFunction(high);
	}
	
	private void closeFiles() {
		//for (PrintWriter pw : pws.values()) {
		//	pw.flush();
		//	pw.close();
		//}
		ia.close();
	}
	
	private HighFunction getHighFunction(DecompInterface ifc, Function func) {
		DecompileResults res = ifc.decompileFunction(func, 300, null);
		HighFunction high = res.getHighFunction();
		if (high == null) {
			System.err.println(func+" returned null HighFunction");
		}
		return high;
	}

	private void export(String label, String key, String value) {
		key = key.replaceAll(QUOTE, "'");
		value = value.replaceAll(QUOTE, "'");
		if (!decls.contains(label)) {
			ia.println("table "+label+"[string, string]");
			decls.add(label);
		}
		if (!pairs.containsKey(label+key)) {
			ia.println(label+"["+QUOTE+key+QUOTE+","+QUOTE+value+QUOTE+"]");
			pairs.put(label+key, value);
		}
	}
	
	private void exportL(String label, String key, long value) {
		key = key.replaceAll(QUOTE, "'");
		if (!decls.contains(label)) {
			ia.println("table " + label + "[string, int]");
			decls.add(label);
		}
		if (!pairs.containsKey(label + key)) {
			ia.println(label + "[" + QUOTE + key + QUOTE + "," + value + "]");
			pairs.put(label + key, Long.toString(value));
		}
	}

	private void exportN(String label, String key, int index, String value) {
		key = key.replaceAll(QUOTE, "'");
		value = value.replaceAll(QUOTE, "'");
		if (!decls.contains(label)) {
			if (value.equals("")) {
				ia.println("table "+label+"[string, int]");
			} else {
				ia.println("table "+label+"[string, int, string]");
			}
			decls.add(label);
		}
		if (!pairs.containsKey(label+key+index)) {
			if (value.equals("")) {
				ia.println(label+"["+QUOTE+key+QUOTE+","+index+"]");
			} else {
				ia.println(label+"["+QUOTE+key+QUOTE+","+index+","+QUOTE+value+QUOTE+"]");
			}
			pairs.put(label+key+index, value);
		}
	}

	private void exportNL(String label, String key, int index, long value) {
		key = key.replaceAll(QUOTE, "'");
		if (!decls.contains(label)) {
			ia.println("table " + label + "[string, int, int]");
			decls.add(label);
		}
		if (!pairs.containsKey(label + key + index)) {
			ia.println(label + "[" + QUOTE + key + QUOTE + "," + index + "," + value + "]");
			pairs.put(label + key + index, Long.toString(value));
		}
	}

	private void exportPcode(HighFunction hfn, PcodeOpAST op) {
		SequenceNumber sn = op.getSeqnum();
		String outstr = op.toString();
		if (sn != null) {
			outstr = sn.getTarget()+SEP+sn.getTime();
		}
		String id = pcodeID(hfn,op);
		export("PCODE_TOSTR",			id, funcID(hfn.getFunction())+SEP+outstr);
		export("PCODE_MNEMONIC",		id, op.getMnemonic());
		export("PCODE_OPCODE",			id, Integer.toString(op.getOpcode()));
		export("PCODE_PARENT",			id, bbID(hfn,op.getParent()));
		export("PCODE_TARGET",			id, op.getSeqnum().getTarget().toString());
		exportN("PCODE_INPUT_COUNT",	id, op.getNumInputs(), "");
		for (int i = 0; i < op.getNumInputs(); ++i) {
			VarnodeAST vni = (VarnodeAST) op.getInput(i);
			if (vni != null) {
				// OK, this is a little weird, but PTRSUBs with first arg == 0 
				// are (usually) global variables at address == second arg
				if (op.getMnemonic().equals("PTRSUB") && (i == 0)) {
					if (vni.getAddress().getOffset() == 0) {
						VarnodeAST next = (VarnodeAST) op.getInput(1);
						HighVariable high = next.getHigh();
						if (high != null) {
							extraGlobals.put(high, next);
						}
					} 
				}
				exportN("PCODE_INPUT", 	id, i, vnodeID(hfn,vni));
				exportVarnode(hfn,vni);
			}
		}
		VarnodeAST vno = (VarnodeAST) op.getOutput();
		if (vno != null) {
			export("PCODE_OUTPUT", 		id, vnodeID(hfn,vno));
			exportVarnode(hfn, vno);
		}
	}

	private void exportVarnode(HighFunction hfn, VarnodeAST vn) {
		String id = vnodeID(hfn,vn);
		export("VNODE_ADDRESS",			id, vn.getAddress().toString());
		if (vn.isAddress()) {
			export("VNODE_IS_ADDRESS",	id, "true");
		}
		if (vn.isAddrTied()) {
			export("VNODE_IS_ADDRTIED",	id, "true");
		}
		export("VNODE_PC_ADDRESS",		id, vn.getPCAddress().toString());
		export("VNODE_DESC",			id, vn.toString());
		long offset = vn.getOffset();
        exportL("VNODE_OFFSET",            id, offset);
        if (offset < Integer.MAX_VALUE && offset > Integer.MIN_VALUE) {
            exportL("VNODE_OFFSET_N",      id, offset);
        }
		export("VNODE_SIZE",			id, Integer.toString(vn.getSize()));
		export("VNODE_SPACE",			id, vn.getAddress().getAddressSpace().getName());
		HighVariable hv = vn.getHigh();
		if (hv == null) {
			//export("VNODE_TOSTR",		id, funcID(hfn.getFunction())+SEP+vn.toString());
			export("VNODE_TOSTR",		id, funcID(hfn.getFunction())+SEP+vn.getPCAddress().toString()+SEP+vn.toString());
		} else {
			if (hv instanceof HighConstant && hv.getDataType() instanceof Pointer) {
				if (offset != 0) {
					extraGlobals.put(hv, vn);
				}
			}
			//export("VNODE_TOSTR",		id, funcID(hfn.getFunction())+hvarName(hfn,hv));
			export("VNODE_TOSTR",		id, funcID(hfn.getFunction())+SEP+vn.getPCAddress().toString()+SEP+hvarName(hfn,hv));
			export("VNODE_HVAR",		id, hvarID(hfn,hv));
			exportHighVariable(hfn, hv, true);
		}
		if (vn.getDef() != null) {
			export("VNODE_DEF", 		id, pcodeID(hfn, vn.getDef()));
		}
	}

	private void exportHighVariable(HighFunction hfn, HighVariable hv, boolean dontDescend) {
		String id = hvarID(hfn,hv);
		export("HVAR_NAME",				id, hvarName(hfn,hv));
		export("HVAR_SIZE",				id, Integer.toString(hv.getSize()));
		if (hv instanceof HighGlobal) {
			export("HVAR_CLASS",		id, "global");
		}
		if (hv instanceof HighLocal) {
			export("HVAR_CLASS",		id, "local");
			Address pcAddress = ((HighLocal)hv).getPCAddress();
			if (pcAddress != null) {
				export("HVAR_SCOPE",	id, pcAddress.toString());
			}
		}
		if (hv instanceof HighConstant) {
			export("HVAR_CLASS",		id, "constant");
		}
		if (hv instanceof HighOther) {
			export("HVAR_CLASS",		id, "other");
		}
		DataType dataType = hv.getDataType();
		if (dataType != null) {
			export("HVAR_TYPE",			id, dtID(dataType));
			exportType(dataType);
		}
		if (!dontDescend) {
			VarnodeAST representative = (VarnodeAST) hv.getRepresentative();
			if (representative != null) {
				export("HVAR_REPRESENTATIVE",	id, vnodeID(hfn,representative));
				exportVarnode(hfn, representative);
			}
			Varnode[] instances = hv.getInstances();
			for (Varnode varnode : instances) {
				exportVarnode(hfn, (VarnodeAST)varnode);
			}
		}		
	}

	private void exportType(DataType dataType) {
		String id = dtID(dataType);
		if (types.contains(id)) return;
		types.add(id);
		
		export("TYPE_NAME",				id, id);
		exportN("TYPE_LENGTH",			id, dataType.getLength(), "");
		while (dataType instanceof TypeDef) {
			TypeDef typedef = (TypeDef) dataType;
			dataType = typedef.getBaseDataType();
		}
		if (dataType instanceof Pointer) {
			export("TYPE_POINTER", 		id, "true");
			DataType baseType = ((Pointer) dataType).getDataType();
			if (baseType != null) {
				export("TYPE_POINTER_BASE", id, dtID(baseType));
				exportType(baseType);
			} else {
				System.err.println("TEST");
			}
		}
		if (dataType instanceof Array) {
			export("TYPE_ARRAY", 		id, "true");
			Array arr = (Array) dataType;
			export("TYPE_ARRAY_BASE", 	id, dtID(arr.getDataType()));
			exportN("TYPE_ARRAY_N", 	id, arr.getNumElements(), "");
			exportN("TYPE_ARRAY_ELEMENT_LENGTH", id, arr.getElementLength(), "");
			exportType(arr.getDataType());
		}
		if (dataType instanceof Structure) {
			export("TYPE_STRUCT", 		id, "true");
			Structure struct = (Structure) dataType;
			exportN("TYPE_STRUCT_FIELD_COUNT", id, struct.getNumComponents(), "");
			for (int i = 0; i < struct.getNumComponents(); i++) {
				DataTypeComponent dtc = struct.getComponent(i);
				exportComponent("TYPE_STRUCT", id, i, dtc);
			}
		}
		if (dataType instanceof Union) {
			export("TYPE_UNION", 		id, "true");
			Union union = (Union) dataType;
			exportN("TYPE_UNION_FIELD_COUNT", id, union.getNumComponents(), "");
			for (int i = 0; i < union.getNumComponents(); i++) {
				DataTypeComponent dtc = union.getComponent(i);
				exportComponent("TYPE_UNION", id, i, dtc);
			}
		}
		if (dataType instanceof FunctionDefinition) {
			export("TYPE_FUNC", 		id, "true");
			FunctionDefinition fd = (FunctionDefinition) dataType;
			export("TYPE_FUNC_RET", 	id, fd.getReturnType().toString());
			exportType(fd.getReturnType());
			export("TYPE_FUNC_VARARGS", id, Boolean.toString(fd.hasVarArgs()));
			ParameterDefinition[] arguments = fd.getArguments();
			exportN("TYPE_FUNC_PARAM_COUNT", id, arguments.length, "");
			for (int i = 0; i < arguments.length; i++) {
				exportN("TYPE_FUNC_PARAM", id, i, arguments[i].toString());
				exportType(arguments[i].getDataType());
			}
		}
		if (dataType instanceof BooleanDataType) {
			export("TYPE_BOOLEAN", 		id, "true");
		}
		if (dataType instanceof AbstractIntegerDataType) {
			export("TYPE_INTEGER", 		id, "true");
		}
		if (dataType instanceof AbstractFloatDataType) {
			export("TYPE_FLOAT", 		id, "true");
		}
		if (dataType instanceof Enum) {
			export("TYPE_ENUM", 		id, "true");
		}
	}

	private void exportComponent(String label, String id, int i, DataTypeComponent dtc) {
		String dtcid = dtID(dtc.getDataType());
		exportN(label+"_FIELD", 		id, i, dtcid);
        exportNL(label+"_OFFSET",       id, i, dtc.getOffset());
        exportNL(label+"_OFFSET_N",     id, i, dtc.getOffset());
		if (dtc.getFieldName() != null) {
            exportN(label+"_FIELD_NAME", 	id, i, dtc.getFieldName());
			exportN(label+"_FIELD_NAME_BY_OFFSET", id, dtc.getOffset(), dtc.getFieldName());
		}
		exportType(dtc.getDataType());
	}

	private void exportHighFunction(HighFunction hfn) {
		for (PcodeBlockBasic bb : hfn.getBasicBlocks()) {
			String bbid = bbID(hfn,bb);
			export("BB_HFUNC", 			bbid, hfuncID(hfn));
			if (bb.getStart() != null) {
				export("BB_START", 		bbid, bb.getStart().toString());
			}
			for (int i = 0; i < bb.getInSize(); i++) {
				export("BB_IN", 		bbid, bbID(hfn,bb.getIn(i)));
			}
			for (int i = 0; i < bb.getOutSize(); i++) {
				export("BB_OUT", 		bbid, bbID(hfn,bb.getOut(i)));
			}
			if (bb.getOutSize() > 1) {
				export("BB_TOUT", 		bbid, bbID(hfn,bb.getTrueOut()));
				export("BB_FOUT", 		bbid, bbID(hfn,bb.getFalseOut()));
			}
		}
		String id = hfuncID(hfn);
		export("HFUNC_FUNC", 			id, funcID(hfn.getFunction()));
		export("HFUNC_TOSTR", 			id, funcID(hfn.getFunction()));
		export("HFUNC_CSPEC", 			id, hfn.getCompilerSpec().toString());
		export("HFUNC_LANG", 			id, hfn.getLanguage().toString());
		export("HFUNC_EP", 				id, hfn.getFunction().getEntryPoint().toString());
		FunctionPrototype proto = hfn.getFunctionPrototype();
		if (proto != null) {
			export("HFUNC_PROTO",		id, funcID(hfn.getFunction()));
			exportPrototype(hfn, proto, funcID(hfn.getFunction()));
		}
		Function f = hfn.getFunction();
		Function thunk = f.getThunkedFunction(false);
		if (thunk != null && thunk.isExternal()) {
			export("HFUNC_ISEXT",		id, "true");
		}
		if (isEP.contains(f)) {
		        export("HFUNC_ISEP", id, "true");
		}
 		
		Iterator<HighSymbol> symbols = hfn.getLocalSymbolMap().getSymbols();
		while (symbols.hasNext()) {
			HighSymbol hs = symbols.next();
			String hsid = hsID(hfn,hs);
			export("SYMBOL_HFUNC",		hsid, id);
			HighVariable hv = hs.getHighVariable();
			if (hv != null) {
			    export("SYMBOL_HVAR", 		hsid, hvarID(hfn,hv));
			    exportHighVariable(hfn, hv, false);
			}
		}
	}

	private void exportPrototype(HighFunction hfn, FunctionPrototype proto, String id) {
		exportN("PROTO_PARAMETER_COUNT",	id, proto.getNumParams(), "");
		for (int i = 0; i < proto.getNumParams(); i++) {
			HighParam param = proto.getParam(i);
            exportN("PROTO_PARAMETER",        id, i, hvarID(hfn,param));
            exportN("PROTO_PARAMETER_S",      id, i, hvarID(hfn,param));
			export("PROTO_PARAMETER_DATATYPE",	hvarID(hfn,param), dtID(param.getDataType()));
			exportType(param.getDataType());
			VarnodeAST rep = (VarnodeAST) param.getRepresentative();
			export("PROTO_REPRESENTATIVE",	hvarID(hfn,param), vnodeID(hfn, rep));
			exportVarnode(hfn, rep);
		}
		/*
		ParameterDefinition[] parameterDefinitions = proto.getParameterDefinitions();
		if (parameterDefinitions != null) {
			for (ParameterDefinition def : parameterDefinitions) {
				exportN("PROTO_PARAMETER_DEFINITION", id, def.getOrdinal(), def.getName());
				export("PROTO_PARAMETER_DATATYPE", def.getName(), dtID(def.getDataType()));
				exportType(def.getDataType());
			}
		}
		*/
		DataType returnType = proto.getReturnType();
		export("PROTO_RETTYPE", 		id, dtID(returnType));
		exportType(returnType);
		GenericCallingConvention cc = proto.getGenericCallingConvention();
		if (cc != null) {
			export("PROTO_CALLING_CONVENTION", id, cc.toString());
		}
		export("PROTO_IS_VOID", 		id, Boolean.toString(proto.hasNoReturn()));
		export("PROTO_HAS_THIS", 		id, Boolean.toString(proto.hasThisPointer()));
		export("PROTO_IS_VARARG", 		id, Boolean.toString(proto.isVarArg()));
		export("PROTO_IS_INLINE", 		id, Boolean.toString(proto.isInline()));
		export("PROTO_IS_CONSTRUCTOR", 	id, Boolean.toString(proto.isConstructor()));
		export("PROTO_IS_DESTRUCTOR", 	id, Boolean.toString(proto.isDestructor()));
	}

	private void exportPcodeOpSequence(HighFunction hfn, HashSet<PcodeOp> set) {
		Iterator<PcodeOpAST> opiter = hfn.getPcodeOps();
		HashSet<PcodeBlockBasic> seenParents = new HashSet<PcodeBlockBasic>();
		HashMap<PcodeBlock, PcodeOp> first = new HashMap<PcodeBlock, PcodeOp>();
		HashMap<PcodeBlock, PcodeOp> last = new HashMap<PcodeBlock, PcodeOp>();
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			PcodeBlockBasic parent = op.getParent();
			if (seenParents.contains(parent)) {
				continue;
			}
			Iterator<PcodeOp> iterator = parent.getIterator();
			PcodeOp prev = null;
			PcodeOp next = null;
			while (iterator.hasNext()) {
				next = iterator.next();
				if (prev == null && set.contains(next)) {
					first.put(parent, next);
				}
				if (prev != null && set.contains(prev) && set.contains(next)) {
					export("PCODE_NEXT", pcodeID(hfn, prev), pcodeID(hfn, next));
				}
				prev = next;
			}
			if (next != null && set.contains(next)) {
				last.put(parent, next);
			}
			seenParents.add(parent);
		}
		for (PcodeBlock block : first.keySet()) {
			PcodeOpAST ast = (PcodeOpAST) first.get((block));
			export("BB_FIRST", bbID(hfn, block), pcodeID(hfn, ast));
		}
		for (PcodeBlock block : last.keySet()) {
			export("BB_LAST", bbID(hfn, block), pcodeID(hfn, last.get(block)));
		}
	}

	private String pcodeID(HighFunction hfn, PcodeOp op) {
		SequenceNumber sn = op.getSeqnum();
		if (sn != null) {
			return hfuncID(hfn)+SEP+sn.getTarget()+SEP+sn.getTime();
		}
		return hfuncID(hfn)+SEP+"NO_SEQNUM"+SEP+op.toString();
	}
	
	private String vnodeID(HighFunction hfn, VarnodeAST vn) {
		return hfuncID(hfn)+SEP+Integer.toString(vn.getUniqueId());
	}

	private String hvarID(HighFunction hfn, HighVariable hv) {
		return hfuncID(hfn)+SEP+hvarName(hfn, hv);
	}
	private String hvarName(HighFunction hfn, HighVariable hv) {
		if (hv.getName() == null) {
			SymbolTable symbolTable = hfn.getFunction().getProgram().getSymbolTable();
			Varnode rep = hv.getRepresentative();
			Address addr = rep.getAddress();
			if (extraGlobals.containsKey(hv)) {
				VarnodeAST vn = extraGlobals.get(hv);
				addr = currentAddress.getNewAddress(vn.getOffset());
			} 
			Symbol symbol = symbolTable.getPrimarySymbol(addr);
			if (symbol == null) {
				return Integer.toString(hv.hashCode());
			}
			export("HVAR_CLASS", hfuncID(hfn)+SEP+symbol.getName(), "global");
			return symbol.getName();
		}
		return hv.getName();
	}

	private String hsID(HighFunction hfn, HighSymbol hs) {
		return hfuncID(hfn)+SEP+hs.getName();
	}
	
	private String funcID(Function fn) {
		return fn.getName(true)+"@"+fn.getEntryPoint();
	}
	
	private String hfuncID(HighFunction fn) {
		return fn.toString();
	}
	
	private String bbID(HighFunction hfn, PcodeBlock bb) {
		if (bb.getStart() != null) {
			return hfuncID(hfn)+SEP+bb.hashCode();
		}
		return hfuncID(hfn)+SEP+"unknown block";
	}

	private String dtID(DataType dt) {
		if (dt.getName() != null) {
			return dt.getName().replaceAll(" ", "");
		}
		return dt.toString();
	}

}
