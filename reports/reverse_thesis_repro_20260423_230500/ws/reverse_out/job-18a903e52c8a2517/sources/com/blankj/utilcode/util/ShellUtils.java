package com.blankj.utilcode.util;

import com.blankj.utilcode.util.Utils;
import java.util.List;

/* JADX INFO: loaded from: classes.dex */
public final class ShellUtils {
    private static final String LINE_SEP = System.getProperty("line.separator");

    private ShellUtils() {
        throw new UnsupportedOperationException("u can't instantiate me...");
    }

    public static Utils.Task<CommandResult> execCmdAsync(String command, boolean isRooted, Utils.Callback<CommandResult> callback) {
        return execCmdAsync(new String[]{command}, isRooted, true, callback);
    }

    public static Utils.Task<CommandResult> execCmdAsync(List<String> commands, boolean isRooted, Utils.Callback<CommandResult> callback) {
        return execCmdAsync(commands == null ? null : (String[]) commands.toArray(new String[0]), isRooted, true, callback);
    }

    public static Utils.Task<CommandResult> execCmdAsync(String[] commands, boolean isRooted, Utils.Callback<CommandResult> callback) {
        return execCmdAsync(commands, isRooted, true, callback);
    }

    public static Utils.Task<CommandResult> execCmdAsync(String command, boolean isRooted, boolean isNeedResultMsg, Utils.Callback<CommandResult> callback) {
        return execCmdAsync(new String[]{command}, isRooted, isNeedResultMsg, callback);
    }

    public static Utils.Task<CommandResult> execCmdAsync(List<String> commands, boolean isRooted, boolean isNeedResultMsg, Utils.Callback<CommandResult> callback) {
        return execCmdAsync(commands == null ? null : (String[]) commands.toArray(new String[0]), isRooted, isNeedResultMsg, callback);
    }

    public static Utils.Task<CommandResult> execCmdAsync(final String[] commands, final boolean isRooted, final boolean isNeedResultMsg, Utils.Callback<CommandResult> callback) {
        if (callback == null) {
            throw new NullPointerException("Argument 'callback' of type Utils.Callback<CommandResult> (#3 out of 4, zero-based) is marked by @android.support.annotation.NonNull but got null for it");
        }
        return Utils.doAsync(new Utils.Task<CommandResult>(callback) { // from class: com.blankj.utilcode.util.ShellUtils.1
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // com.blankj.utilcode.util.Utils.Task
            public CommandResult doInBackground() {
                return ShellUtils.execCmd(commands, isRooted, isNeedResultMsg);
            }
        });
    }

    public static CommandResult execCmd(String command, boolean isRooted) {
        return execCmd(new String[]{command}, isRooted, true);
    }

    public static CommandResult execCmd(List<String> commands, boolean isRooted) {
        return execCmd(commands == null ? null : (String[]) commands.toArray(new String[0]), isRooted, true);
    }

    public static CommandResult execCmd(String[] commands, boolean isRooted) {
        return execCmd(commands, isRooted, true);
    }

    public static CommandResult execCmd(String command, boolean isRooted, boolean isNeedResultMsg) {
        return execCmd(new String[]{command}, isRooted, isNeedResultMsg);
    }

    public static CommandResult execCmd(List<String> commands, boolean isRooted, boolean isNeedResultMsg) {
        return execCmd(commands == null ? null : (String[]) commands.toArray(new String[0]), isRooted, isNeedResultMsg);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(19:7|111|8|(1:10)(1:11)|12|(3:14|(2:16|132)(2:17|131)|18)|130|19|(4:21|(2:23|(2:24|(1:26)(1:133)))(0)|27|(11:29|(2:30|(1:32)(0))|35|(2:117|40)|(2:123|46)|(1:52)|77|(1:79)(1:80)|(1:83)|84|85)(0))(0)|128|35|(0)|(0)|(0)|77|(0)(0)|(0)|84|85) */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00cb, code lost:
    
        r0 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:38:0x00cc, code lost:
    
        r0.printStackTrace();
     */
    /* JADX WARN: Removed duplicated region for block: B:117:0x00d1 A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:123:0x00dd A[EXC_TOP_SPLITTER, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:52:0x00e9 A[PHI: r1 r3 r6 r7
      0x00e9: PHI (r1v3 'result' int) = (r1v1 'result' int), (r1v4 'result' int) binds: [B:75:0x0117, B:51:0x00e7] A[DONT_GENERATE, DONT_INLINE]
      0x00e9: PHI (r3v4 'process' java.lang.Process) = (r3v3 'process' java.lang.Process), (r3v5 'process' java.lang.Process) binds: [B:75:0x0117, B:51:0x00e7] A[DONT_GENERATE, DONT_INLINE]
      0x00e9: PHI (r6v3 'successMsg' java.lang.StringBuilder) = (r6v1 'successMsg' java.lang.StringBuilder), (r6v4 'successMsg' java.lang.StringBuilder) binds: [B:75:0x0117, B:51:0x00e7] A[DONT_GENERATE, DONT_INLINE]
      0x00e9: PHI (r7v3 'errorMsg' java.lang.StringBuilder) = (r7v1 'errorMsg' java.lang.StringBuilder), (r7v4 'errorMsg' java.lang.StringBuilder) binds: [B:75:0x0117, B:51:0x00e7] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:79:0x011e  */
    /* JADX WARN: Removed duplicated region for block: B:80:0x0120  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0127  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.blankj.utilcode.util.ShellUtils.CommandResult execCmd(java.lang.String[] r13, boolean r14, boolean r15) {
        /*
            Method dump skipped, instruction units count: 351
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.blankj.utilcode.util.ShellUtils.execCmd(java.lang.String[], boolean, boolean):com.blankj.utilcode.util.ShellUtils$CommandResult");
    }

    public static class CommandResult {
        public String errorMsg;
        public int result;
        public String successMsg;

        public CommandResult(int result, String successMsg, String errorMsg) {
            this.result = result;
            this.successMsg = successMsg;
            this.errorMsg = errorMsg;
        }

        public String toString() {
            return "result: " + this.result + "\nsuccessMsg: " + this.successMsg + "\nerrorMsg: " + this.errorMsg;
        }
    }
}
