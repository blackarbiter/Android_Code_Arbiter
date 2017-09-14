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
package com.h3xstream.findsecbugs.common;

import org.apache.bcel.classfile.Code;
import org.apache.bcel.classfile.CodeException;

import java.util.Map;

/**
 * Created by balckarbiter on 17/8/2.
 */
public class StringCodeAnalysis {
    public Code code;

    public StringCodeAnalysis(Code code){
        this.code = code;
    }

    public StringCodeAnalysis(){}

    public String[] codes_String_Array(){
        String[] codes = this.code.toString().split("\n");
        return codes;
    }

    public String get_First_Code(String[] codes){
        return codes[0];
    }

    public int get_Code_Length(String firstLineCode){
        try{
            String[] split1 = firstLineCode.split("code_length");
//            System.out.println(split1[split1.length-1]);
            byte[] code_length_bytes = split1[split1.length-1].getBytes();
            byte[] new_code_bytes = new byte[code_length_bytes.length];
            for(int i=0; i<code_length_bytes.length; i++){
//                System.out.println();
                if(code_length_bytes[i]<48 || code_length_bytes[i]>57){
                    new_code_bytes[i] = 32;
                }else{
                    new_code_bytes[i] = code_length_bytes[i];
                }
            }
            return Integer.parseInt(new String(new_code_bytes).trim());
        }catch(Exception e){
            e.printStackTrace();
        }
        return 0;
    }

    public int[] getExceptionScope(){
        try {
            CodeException[] exceptionTable = this.code.getExceptionTable();
            int[] exception_scop = new int[exceptionTable.length * 2];
            for (int i = 0; i < exceptionTable.length; i++) {
                exception_scop[i * 2] = exceptionTable[i].getStartPC();
                exception_scop[i * 2 + 1] = exceptionTable[i].getEndPC();
            }
            return exception_scop;
        }catch (Exception e){
//            e.printStackTrace();
        }
        return new int[0];
    }

    public int get_code_line_index(String code_line){
        try {
            String[] split1 = code_line.split(":");
            byte[] line_index = split1[0].getBytes();
            for(int i=0; i<line_index.length; i++){
                if(line_index[i]<48 || line_index[i]>57){
                    line_index[i] = 32;
                }
            }
            return Integer.parseInt(new String(line_index).trim());
        }catch (Exception e){
//            e.printStackTrace();
        }
        return -1;
    }

    private String get_class_name(String code_line){
        if(code_line.contains("android.content.Intent")){
            return "android.content.Intent";
        }
        return "android.os.Bundle";
    }

    private String get_method_name(String code_line){
        String class_name = get_class_name(code_line);
        String[] split1 = code_line.split(class_name + ".");
        String method_name = split1[1].split(" ")[0].trim();
        return method_name;
    }

//    public static void main(String[] args){
//        String firstLineCode = "Code(max_stack = 4, max_locals = 5, code_length = 59)";
//        StringCodeAnalysis sca = new StringCodeAnalysis();
//        System.out.println(sca.get_Code_Length(firstLineCode));
//        String line = "264:  invokevirtual\tandroid.content.Intent.getShortExtra (Ljava/lang/String;S)S (95)";
//        System.out.println(sca.get_code_line_index(firstLineCode));
//        System.out.println(line.contains("invokevirtual"));
//        System.out.println(line.contains("android/content/Intent.get"));
//        System.out.println(line.contains("android/os/Bundle.get"));
//        System.out.println(sca.get_class_name(line));
//        System.out.println(sca.get_method_name(line));
//    }
}
