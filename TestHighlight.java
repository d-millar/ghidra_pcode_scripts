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
//Set program highlight based on results files
//@category PCode

import java.awt.Color;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;

import org.python.jline.internal.InputStreamReader;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressSet;

public class TestHighlight extends GhidraScript {
	
	AddressSet selection = new AddressSet();
	
	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
			return;
		}
		ColorizingService color = tool.getService(ColorizingService.class);
		if (color == null) {
			println("Can't find ColorizingService");
			return;
		}
		File f = askFile("Results File", "OK");
		InputStream in = new FileInputStream(f);
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String line;
		while ((line = br.readLine()) != null) {
			matchLine(color, line);
		}
		this.setCurrentHighlight(selection);
		this.setCurrentSelection(selection);
		br.close();
	}

	private void matchLine(ColorizingService color, String line) {
		String[] tokens = line.split("\t");
		String src = tokens[0];
		String vn = tokens[1];
		String[] subtokens = vn.split(":");
		String addr = subtokens[1];
		try {
			Address address = currentAddress.getAddress(addr);
			selection.add(address);
			Color c = new Color(src.hashCode());
			color.setBackgroundColor(address, address, c);
			selection.add(address);
		} catch (AddressFormatException e) {
			e.printStackTrace();
		}
	}

}
