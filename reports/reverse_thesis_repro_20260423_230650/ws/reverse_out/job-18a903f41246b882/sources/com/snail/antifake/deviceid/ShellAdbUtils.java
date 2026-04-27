package com.snail.antifake.deviceid;

import java.util.List;

/* JADX INFO: loaded from: classes3.dex */
public class ShellAdbUtils {
    public static final String COMMAND_EXIT = "exit\n";
    public static final String COMMAND_LINE_END = "\n";
    public static final String COMMAND_SH = "sh";
    public static final String COMMAND_SU = "su";

    private ShellAdbUtils() {
        throw new AssertionError();
    }

    public static boolean checkRootPermission() {
        return execCommand("echo root", true, false).result == 0;
    }

    public static CommandResult execCommand(String command, boolean isRoot) {
        return execCommand(new String[]{command}, isRoot, true);
    }

    public static CommandResult execCommand(List<String> commands, boolean isRoot) {
        return execCommand(commands == null ? null : (String[]) commands.toArray(new String[0]), isRoot, true);
    }

    public static CommandResult execCommand(String[] commands, boolean isRoot) {
        return execCommand(commands, isRoot, true);
    }

    public static CommandResult execCommand(String command, boolean isRoot, boolean isNeedResultMsg) {
        return execCommand(new String[]{command}, isRoot, isNeedResultMsg);
    }

    public static CommandResult execCommand(List<String> commands, boolean isRoot, boolean isNeedResultMsg) {
        return execCommand(commands == null ? null : (String[]) commands.toArray(new String[0]), isRoot, isNeedResultMsg);
    }

    /* JADX WARN: Can't wrap try/catch for region: R(12:(7:105|8|(1:10)(1:11)|12|(3:14|(2:16|109)(2:17|108)|18)|107|19)|(12:21|(2:22|(1:24)(1:110))|(2:25|(1:27)(0))|30|(1:32)|(1:34)|(1:39)|72|(1:74)(1:75)|(1:78)|79|80)(0)|103|30|(0)|(0)|(0)|72|(0)(0)|(0)|79|80) */
    /* JADX WARN: Code restructure failed: missing block: B:36:0x00a2, code lost:
    
        r8 = move-exception;
     */
    /* JADX WARN: Code restructure failed: missing block: B:37:0x00a3, code lost:
    
        r8.printStackTrace();
     */
    /* JADX WARN: Removed duplicated region for block: B:111:? A[DONT_GENERATE, FINALLY_INSNS, SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:32:0x0099 A[Catch: IOException -> 0x00a2, TryCatch #4 {IOException -> 0x00a2, blocks: (B:30:0x0094, B:32:0x0099, B:34:0x009e), top: B:103:0x0094 }] */
    /* JADX WARN: Removed duplicated region for block: B:34:0x009e A[Catch: IOException -> 0x00a2, TRY_LEAVE, TryCatch #4 {IOException -> 0x00a2, blocks: (B:30:0x0094, B:32:0x0099, B:34:0x009e), top: B:103:0x0094 }] */
    /* JADX WARN: Removed duplicated region for block: B:39:0x00a8 A[PHI: r0 r2 r5 r6
      0x00a8: PHI (r0v4 'result' int) = (r0v1 'result' int), (r0v2 'result' int), (r0v5 'result' int) binds: [B:55:0x00ca, B:70:0x00e9, B:38:0x00a6] A[DONT_GENERATE, DONT_INLINE]
      0x00a8: PHI (r2v6 'process' java.lang.Process) = (r2v3 'process' java.lang.Process), (r2v4 'process' java.lang.Process), (r2v7 'process' java.lang.Process) binds: [B:55:0x00ca, B:70:0x00e9, B:38:0x00a6] A[DONT_GENERATE, DONT_INLINE]
      0x00a8: PHI (r5v4 'successMsg' java.lang.StringBuilder) = 
      (r5v1 'successMsg' java.lang.StringBuilder)
      (r5v2 'successMsg' java.lang.StringBuilder)
      (r5v5 'successMsg' java.lang.StringBuilder)
     binds: [B:55:0x00ca, B:70:0x00e9, B:38:0x00a6] A[DONT_GENERATE, DONT_INLINE]
      0x00a8: PHI (r6v4 'errorMsg' java.lang.StringBuilder) = 
      (r6v1 'errorMsg' java.lang.StringBuilder)
      (r6v2 'errorMsg' java.lang.StringBuilder)
      (r6v5 'errorMsg' java.lang.StringBuilder)
     binds: [B:55:0x00ca, B:70:0x00e9, B:38:0x00a6] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x00f0  */
    /* JADX WARN: Removed duplicated region for block: B:75:0x00f2  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x00f9  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x011b A[DONT_GENERATE, FINALLY_INSNS] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.snail.antifake.deviceid.ShellAdbUtils.CommandResult execCommand(java.lang.String[] r12, boolean r13, boolean r14) {
        /*
            Method dump skipped, instruction units count: 293
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.snail.antifake.deviceid.ShellAdbUtils.execCommand(java.lang.String[], boolean, boolean):com.snail.antifake.deviceid.ShellAdbUtils$CommandResult");
    }

    public static class CommandResult {
        public String errorMsg;
        public int result;
        public String successMsg;

        public CommandResult(int result) {
            this.result = result;
        }

        public CommandResult(int result, String successMsg, String errorMsg) {
            this.result = result;
            this.successMsg = successMsg;
            this.errorMsg = errorMsg;
        }
    }
}
