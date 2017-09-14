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
import org.apache.bcel.generic.*;

import java.util.*;

import com.h3xstream.findsecbugs.common.StringCodeAnalysis;
/**
 * Created by blackarbiter on 17/8/2.
 */
public class WebViewSslErrorDetector implements Detector{
    private static final String WEBVIEW_RECEIVE_SSL_ERROR_TYPE = "WEBVIEW_RECEIVE_SSL_ERROR";

    private BugReporter bugReporter;

    public WebViewSslErrorDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }
    @Override
    public void visitClassContext(ClassContext classContext) {
        JavaClass javaClass = classContext.getJavaClass();
//        System.out.println(javaClass.getSuperclassName() + "###");
        if(javaClass.getSuperclassName().equals("android.webkit.WebViewClient")) {
            Method[] methodList = javaClass.getMethods();

            for (Method m : methodList) {
//                System.out.println(m.getName() + "###");
                if(m.getName().equals("onReceivedSslError")) {
                    try {
                        analyzeMethod(javaClass, m, classContext);
                    } catch (CFGBuilderException e) {
                    }
                }
            }
        }
    }

    @Override
    public void report() {

    }

    private void analyzeMethod(JavaClass javaClass, Method m, ClassContext classContext) throws CFGBuilderException {
        MethodGen methodGen = classContext.getMethodGen(m);
        ConstantPoolGen cpg = classContext.getConstantPoolGen();
        CFG cfg = classContext.getCFG(m);

        if (methodGen == null || methodGen.getInstructionList() == null) {
            bugReporter.reportBug(new BugInstance(this, WEBVIEW_RECEIVE_SSL_ERROR_TYPE, HIGH_PRIORITY)
                    .addClass(javaClass)
                    .addMethod(javaClass, m)
            );
        }
        for (Iterator<Location> i = cfg.locationIterator(); i.hasNext(); ) {
            Location location = i.next();
            Instruction inst = location.getHandle().getInstruction();
            if (inst instanceof INVOKEVIRTUAL) {
                INVOKEVIRTUAL invoke = (INVOKEVIRTUAL) inst;
                String methodName = invoke.getMethodName(cpg);
                if ("proceed".equals(methodName)) {
                    bugReporter.reportBug(new BugInstance(this, WEBVIEW_RECEIVE_SSL_ERROR_TYPE, HIGH_PRIORITY)
                            .addClass(javaClass)
                            .addMethod(javaClass, m)
                            .addCalledMethod(cpg, invoke)
                            .addSourceLine(classContext, m, location)
                    );
                }
                break;
            }
        }
    }
}
