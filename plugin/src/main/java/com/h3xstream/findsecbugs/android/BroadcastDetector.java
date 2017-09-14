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

import com.h3xstream.findsecbugs.injection.BasicInjectionDetector;
import com.h3xstream.findsecbugs.injection.InjectionPoint;
import com.h3xstream.findsecbugs.taintanalysis.Taint;
import com.h3xstream.findsecbugs.taintanalysis.TaintFrame;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.ba.DataflowAnalysisException;
import org.apache.bcel.generic.ConstantPoolGen;
import org.apache.bcel.generic.InstructionHandle;
import org.apache.bcel.generic.InvokeInstruction;

import java.util.ArrayList;
import java.util.List;

public class BroadcastDetector extends BasicInjectionDetector {

    private static final String ANDROID_BROADCAST_TYPE = "ANDROID_BROADCAST";

    public BroadcastDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    protected int getPriorityFromTaintFrame(TaintFrame fact, int offset)
            throws DataflowAnalysisException {
        Taint stringValue = fact.getStackValue(offset);
//        System.out.println(stringValue.getConstantValue());
        if (stringValue.getConstantValue() == null) { //Is a constant value
            return Priorities.NORMAL_PRIORITY;
        } else {
            return Priorities.IGNORE_PRIORITY;
        }
    }

    @Override
    protected InjectionPoint getInjectionPoint(InvokeInstruction invoke, ConstantPoolGen cpg,
                                               InstructionHandle handle) {
        assert invoke != null && cpg != null;

        String method = invoke.getMethodName(cpg);
        String sig    = invoke.getSignature(cpg);
//        System.out.println(sig);
        if(sig.contains("Ljava/lang/String;")) {
            if(method.contains("send") && method.contains("Broadcast") && !method.contains("Sticky")){
//                System.out.println(method);
                if("sendOrderedBroadcastAsUser".equals(method)){
                    return new InjectionPoint(new int[]{5}, ANDROID_BROADCAST_TYPE);
                }
                if("sendOrderedBroadcast".equals(method) && sig.contains("Landroid/content/BroadcastReceiver;")){
                    return new InjectionPoint(new int[]{5}, ANDROID_BROADCAST_TYPE);
                }
                return new InjectionPoint(new int[]{0}, ANDROID_BROADCAST_TYPE);
            }
        }
        return InjectionPoint.NONE;
    }
}
