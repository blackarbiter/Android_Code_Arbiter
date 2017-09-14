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

/**
 * Created by blackarbiter on 17/8/2.
 */
public class RegisterReceiverPermissionDetector extends BasicInjectionDetector{
    private static final String ANDROID_REGISTER_RECEIVER_TYPE = "ANDROID_REGISTER_RECEIVER";

    public RegisterReceiverPermissionDetector(BugReporter bugReporter) {
        super(bugReporter);
    }

    @Override
    protected int getPriorityFromTaintFrame(TaintFrame fact, int offset)
            throws DataflowAnalysisException {
        Taint stringValue = fact.getStackValue(offset);
        System.out.println(stringValue.getConstantValue());
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

        if(method.equals("registerReceiver")){
            if(sig.contains("Ljava/lang/String;")){
                if(sig.contains(";I)")){
                    return new InjectionPoint(new int[]{2}, ANDROID_REGISTER_RECEIVER_TYPE);
                }else{
                    return new InjectionPoint(new int[]{1}, ANDROID_REGISTER_RECEIVER_TYPE);
                }
            }
        }
        return InjectionPoint.NONE;
    }
}
