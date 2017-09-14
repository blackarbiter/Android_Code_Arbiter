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
 * Created by blackarbiter on 17/8/3.
 */

public class WebViewLoadDataDetector extends BasicInjectionDetector{
    private static final String WEBVIEW_LOAD_DATA_URL_TYPE = "WEBVIEW_LOAD_DATA_URL";

    public WebViewLoadDataDetector(BugReporter bugReporter) {
        super(bugReporter);
    }
    @Override
    protected int getPriorityFromTaintFrame(TaintFrame fact, int offset)
            throws DataflowAnalysisException {
        Taint stringValue = fact.getStackValue(offset);
//        System.out.println(stringValue.getConstantValue());
        if (stringValue.isTainted() || stringValue.isUnknown()) {
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
//        System.out.println(invoke.getClassName(cpg));
        if(sig.contains("Ljava/lang/String;")) {
            if("loadUrl".equals(method)){
                if(sig.contains("Ljava/util/Map;")){
                    return new InjectionPoint(new int[]{1}, WEBVIEW_LOAD_DATA_URL_TYPE);
                }else{
                    return new InjectionPoint(new int[]{0}, WEBVIEW_LOAD_DATA_URL_TYPE);
                }
            }else if("loadData".equals(method)){
                return new InjectionPoint(new int[]{2}, WEBVIEW_LOAD_DATA_URL_TYPE);
            }else if("loadDataWithBaseURL".equals(method)){
                //BUG
                return new InjectionPoint(new int[]{4}, WEBVIEW_LOAD_DATA_URL_TYPE);
            }
        }
        return InjectionPoint.NONE;
    }
}
