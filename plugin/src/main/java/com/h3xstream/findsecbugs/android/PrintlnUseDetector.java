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

import edu.umd.cs.findbugs.BugInstance;
import edu.umd.cs.findbugs.BugReporter;
import edu.umd.cs.findbugs.Priorities;
import edu.umd.cs.findbugs.bcel.OpcodeStackDetector;
import org.apache.bcel.Constants;
/**
 * Created by balckarbiter on 17/8/1.
 */
public class PrintlnUseDetector extends OpcodeStackDetector{

    private static final String OUT_ERR_PRINT_LN_TYPE = "OUT_ERR_PRINT_LN_USE";
    private BugReporter bugReporter;

    public PrintlnUseDetector(BugReporter bugReporter) {
        this.bugReporter = bugReporter;
    }

    @Override
    public void sawOpcode(int seen) {
        if (seen == Constants.INVOKEVIRTUAL && ( //List of method mark as external file access
                getNameConstantOperand().equals("println") ||
                getNameConstantOperand().equals("print")
        ) && getClassConstantOperand().equals("java/io/PrintStream")) {
//            System.out.println(getClassConstantOperand());
            bugReporter.reportBug(new BugInstance(this, OUT_ERR_PRINT_LN_TYPE, Priorities.NORMAL_PRIORITY) //
                    .addClass(this).addMethod(this).addSourceLine(this));
        }
    }
}
