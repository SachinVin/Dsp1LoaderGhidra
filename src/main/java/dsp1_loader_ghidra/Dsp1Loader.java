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
package dsp1_loader_ghidra;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import dsp1_loader_ghidra.Dsp1Header.Segment;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractProgramWrapperLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.model.DomainObject;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this loader does.
 */
public class Dsp1Loader extends AbstractProgramWrapperLoader {
    static final int DSP_DATA_OFFSET = 0x40000;


    @Override
    public String getName() {

        // TODO: Name the loader.  This name must match the name of the loader in the .opinion 
        // files.

        return "3DS DSP Binary (DSP1)";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        List<LoadSpec> loadSpecs = new ArrayList<>();

        // TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
        // can load it, return the appropriate load specifications.
        if(new String(provider.readBytes(0x100, 4)).equals("DSP1"))
            loadSpecs.add(new LoadSpec(this, 0, new LanguageCompilerSpecPair("teak:LE:16:default", "default"), true));
        return loadSpecs;
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
            Program program, TaskMonitor monitor, MessageLog log)
                    throws CancelledException, IOException {

        // TODO: Load the bytes from 'provider' into the 'program'.
        AddressSpace addressSpace = program.getAddressFactory().getDefaultAddressSpace();
        InputStream is = provider.getInputStream(0);

        FlatProgramAPI api = new FlatProgramAPI(program, monitor);
        api.addEntryPoint(api.toAddr(0));
        api.createFunction(api.toAddr(0), "_reset");

        Dsp1Header header = new Dsp1Header(is);
        header.logFields(log);

        if(header.loadSpecialSegment == 1) {
            try {
                long start = header.specialSegmentType == 2 ? DSP_DATA_OFFSET + header.specialSegmentAddress*2 : header.specialSegmentAddress*2 ;
                String segmentName = "Special Segment " + (header.specialSegmentType == 2 ? "Data " : "Prog ") + Long.toHexString(header.specialSegmentAddress);
                MemoryBlockUtils.createInitializedBlock(program, 
                        false, 
                        segmentName, 
                        addressSpace.getAddress(start),
                        // provider.getInputStream(s.offset),
                        header.specialSegmentSize, "", null, true, true, 
                        header.specialSegmentType != 2/*!Data*/, null);
            } catch (AddressOutOfBoundsException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        for (int i = 0; i < Math.min(header.numSegments, 10); i ++) {
            Segment s = header.segments[i];

            try {
                long start = s.isData() ? DSP_DATA_OFFSET + s.address*2 : s.address*2 ;

                String segmentName = "Segment " + (s.isData() ? "Data " : "Prog ") + Long.toHexString(s.address);
                MemoryBlockUtils.createInitializedBlock(program, 
                        false, 
                        segmentName, 
                        addressSpace.getAddress(start),
                        provider.getInputStream(s.offset),
                        s.size, "", null, true, true, 
                        !s.isData(), null, 
                        monitor);
            } catch (AddressOverflowException | AddressOutOfBoundsException | IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
        is.close();
    }

    @Override
    public List<Option> getDefaultOptions(ByteProvider provider, LoadSpec loadSpec,
            DomainObject domainObject, boolean isLoadIntoProgram) {
        List<Option> list =
                super.getDefaultOptions(provider, loadSpec, domainObject, isLoadIntoProgram);

        // TODO: If this loader has custom options, add them to 'list'
        list.add(new Option("Option name goes here", "Default option value goes here"));

        return list;
    }

    @Override
    public String validateOptions(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program) {

        // TODO: If this loader has custom options, validate them here.  Not all options require
        // validation.

        return super.validateOptions(provider, loadSpec, options, program);
    }
}
