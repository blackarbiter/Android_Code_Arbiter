/**
 * Find Security Bugs
 * Copyright (c) Philippe Arteau, All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3.0 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.
 */
package com.h3xstream.findsecbugs.android;

import com.h3xstream.findsecbugs.common.ByteCode;
import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Detector;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.CFG;
import edu.umd.cs.findbugs.ba.CFGBuilderException;
import edu.umd.cs.findbugs.ba.ClassContext;
import edu.umd.cs.findbugs.ba.Location;
import org.apache.bcel.classfile.*;
import org.apache.bcel.generic.ALOAD;
import org.apache.bcel.generic.ASTORE;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.INVOKESPECIAL;
import org.apache.bcel.generic.INVOKEVIRTUAL;
import org.apache.bcel.generic.Instruction;

import java.util.*;

import org.apache.bcel.generic.InstructionHandle;

import com.h3xstream.findsecbugs.common.StringCodeAnalysis;

/**
 * Created by blackarbiter on 17/8/2.
 */
public class LocalDenialOfServiceDetector implements Detector{
    private static final String LOCAL_DENIAL_SERVICE_TYPE = "LOCAL_DENIAL_SERVICE";

    private BugReporter bugReporter;

    public LocalDenialOfServiceDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }
    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();

        Method[] methodList = javaClass.getMethods();

        for (Method m : methodList) {
            try {
                analyzeMethod(javaClass, m, classContext);
            } catch (CFGBuilderException e) {
            }
        }
    }

    private void analyzeMethod(JavaClass javaClass, Method m, ClassContext classContext) throws CFGBuilderException {
        HashMap<String, List<Location>> all_line_location = (HashMap<String, List<Location>>) get_line_location(m, classContext);
        Code code = m.getCode();
        StringCodeAnalysis sca = new StringCodeAnalysis(code);
        String[] codes = sca.codes_String_Array();
        int code_length = sca.get_Code_Length(sca.get_First_Code(codes));
        int[] exception_scop = sca.getExceptionScope();
        for(int i=1; i<codes.length; i++){
            int line_index = sca.get_code_line_index(codes[i]);
            if (line_index < code_length){
                if(codes[i].toLowerCase().contains("invokevirtual") &&
                        (codes[i].contains("android.content.Intent.get")  || codes[i].contains("android.os.Bundle.get"))){
                    if(exception_scop.length == 0){
                        String method_name = get_method_name(codes[i]);
                        if(all_line_location.containsKey(method_name)){
                            for(Location loc : all_line_location.get(method_name)){
                                bugReporter.reportBug(new BugInstance(this, LOCAL_DENIAL_SERVICE_TYPE, Priorities.NORMAL_PRIORITY) //
                                        .addClass(javaClass)
                                        .addMethod(javaClass, m)
                                        .addSourceLine(classContext, m, loc));
                            }
                        }else {
                            bugReporter.reportBug(new BugInstance(this, LOCAL_DENIAL_SERVICE_TYPE, Priorities.NORMAL_PRIORITY) //
                                    .addClass(javaClass)
                                    .addMethod(javaClass, m));
//                                .addSourceLine(classContext, m, ));
                        }
                    }else{
                        boolean is_scope = false;
                        for(int j=0; j<exception_scop.length; j+=2){
                            int start = exception_scop[j];
                            int end = exception_scop[j+1];
                            if(line_index >= start && line_index <= end){
                                is_scope = true;
                            }
                            if(is_scope){
                                break;
                            }
                        }
                        if(!is_scope){
                            String method_name = get_method_name(codes[i]);
                            if(all_line_location.containsKey(method_name)){
                                for(Location loc : all_line_location.get(method_name)){
                                    bugReporter.reportBug(new BugInstance(this, LOCAL_DENIAL_SERVICE_TYPE, Priorities.NORMAL_PRIORITY) //
                                            .addClass(javaClass)
                                            .addMethod(javaClass, m)
                                            .addSourceLine(classContext, m, loc));
                                }
                            }else {
                                bugReporter.reportBug(new BugInstance(this, LOCAL_DENIAL_SERVICE_TYPE, Priorities.NORMAL_PRIORITY) //
                                        .addClass(javaClass)
                                        .addMethod(javaClass, m));
//                                .addSourceLine(classContext, m, ));
                            }
                        }
                    }
                }
            }
        }
    }

    private Map<String, List<Location>> get_line_location(Method m, ClassContext classContext){
        HashMap<String, List<Location>> all_line_location = new HashMap<>();
        ConstantPoolGen cpg = classContext.getConstantPoolGen();
        CFG cfg = null;
        try {
            cfg = classContext.getCFG(m);
        } catch (CFGBuilderException e) {
            e.printStackTrace();
            return all_line_location;
        }
        for (Iterator<Location> i = cfg.locationIterator(); i.hasNext(); ) {
            Location loc = i.next();
            Instruction inst = loc.getHandle().getInstruction();
            if(inst instanceof INVOKEVIRTUAL) {
                INVOKEVIRTUAL invoke = (INVOKEVIRTUAL) inst;
//                if (classname.equals(invoke.getClassName(cpg)) &&
//                        methodName.equals(invoke.getMethodName(cpg))) {
                    if(all_line_location.containsKey(invoke.getMethodName(cpg))){
                        all_line_location.get(invoke.getMethodName(cpg)).add(loc);
                    }else {
                        LinkedList<Location> loc_list = new LinkedList<>();
                        loc_list.add(loc);
                        all_line_location.put(invoke.getMethodName(cpg), loc_list);
                    }
//                }
            }
        }
        return all_line_location;
    }

    private String get_class_name(String code_line){
        if(code_line.contains("android.content.Intent")){
            return "android.content.Intent";
        }
        return "android.os.Bundle";
    }

    private String get_method_name(String code_line){
        try {
            String class_name = get_class_name(code_line);
            String[] split1 = code_line.split(class_name + ".");
            String method_name = split1[1].split(" ")[0].trim();
            return method_name;
        }catch (Exception e){
//            e.printStackTrace();
        }
        return "error_get_method_name";
    }

    @Override
    public void report() {

    }
}
