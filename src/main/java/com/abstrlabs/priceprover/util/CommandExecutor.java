package com.abstrlabs.priceprover.util;

import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Log4j2
public class CommandExecutor {

    @SneakyThrows
    public boolean execute(String[] commands) {
        Runtime rt = Runtime.getRuntime();
        Process proc = rt.exec(commands);
        boolean success = true;

        BufferedReader stdInput = new BufferedReader(new
                InputStreamReader(proc.getInputStream()));

        BufferedReader stdError = new BufferedReader(new
                InputStreamReader(proc.getErrorStream()));

        String s;
        // Read the output from the command
        log.info("Here is the standard output of the command:\n");
        while ((s = stdInput.readLine()) != null) {
            log.info(s);
        }
        // Read any errors from the attempted command
        if ((s = stdError.readLine()) != null) {
            success = false;
            log.debug("Here is the standard error of the c:\n");
            log.debug(s);
        }
        while ((s = stdError.readLine()) != null) {
            log.error(s);
        }
        return success;
    }

    public static void main(String[] args) {
        CommandExecutor ce = new CommandExecutor();
        ce.execute(args);
    }
}
