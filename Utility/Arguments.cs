using System.Collections.Generic;
namespace Utility
{
    public class Arguments
    {
        private List<string> _Positionals = new List<string>();
        private Dictionary<string, Convertable> _KeyValue = new Dictionary<string, Convertable>();

        public Arguments(in string[] args, List<string>? positionalKeys = null, List<string>? optionalKeys = null)
        {
            List<string> positionalCandidates = new List<string>();
            int positional_cnt = 0;
            for (var i = 0; i < args.Count(); ++i)
            {
                int? val_i = null;
                double? val_d = null;
                if (args[i].StartsWith("-"))
                {
                    int start_num = args[i].StartsWith("--") ? 2 : 1;
                    if (optionalKeys != null && !optionalKeys.Contains(args[i].Substring(start_num)))
                    {
                        throw new Exception("Unknown Key:" + args[i].Substring(start_num));
                    }
                    if (i + 1 == args.Count() || args[i + 1].StartsWith("-") || args[i + 1] == "true")
                    {
                        _KeyValue[args[i].Substring(start_num)] = true;
                        continue;
                    }
                    else if (args[i + 1] == "false")
                    {
                        _KeyValue[args[i].Substring(start_num)] = false;
                        continue;
                    }
                    try
                    {
                        val_i = Int32.Parse(args[i + 1]);
                        val_d = Double.Parse(args[i + 1]);
                    }
                    catch (Exception)
                    {
                    }
                    if (val_i != null)
                    {
                        _KeyValue[args[i].Substring(start_num)] = val_i;
                    }
                    else if (val_d != null)
                    {
                        _KeyValue[args[i].Substring(start_num)] = val_d;
                    }
                    else
                    {
                        _KeyValue[args[i].Substring(start_num)] = args[i + 1];
                    }
                    ++i;
                }
                else
                {
                    positionalCandidates.Add(args[i]);
                }
            }
            foreach (var item in positionalCandidates)
            {
                if (positionalKeys != null && positional_cnt < positionalKeys.Count)
                {
                    while (positional_cnt < positionalKeys.Count && _KeyValue.Keys.Contains(positionalKeys[positional_cnt]))
                    {
                        positional_cnt++;
                    }
                    if (positional_cnt < positionalKeys.Count)
                    {
                        _KeyValue.Add(positionalKeys[positional_cnt], item);
                        continue;
                    }
                }
                _Positionals.Add(item);
            }
            // check values
            if (positionalKeys != null)
            {
                foreach (var positional in positionalKeys)
                {
                    if (!_KeyValue.Keys.Contains(positional))
                    {
                        throw new Exception("Required Argument: " + positional + ".");
                    }
                }
            }
            if (optionalKeys != null)
            {
                string? target = null;
                foreach (var optional in optionalKeys)
                {
                    if (!_KeyValue.Keys.Contains(optional))
                    {
                        _KeyValue[optional] = target;

                    }
                }
            }
        }

        public override string ToString()
        {
            string ret = "";
            foreach (var kv in _KeyValue)
            {
                if (ret != "")
                {
                    ret += "\n";
                }
                ret += kv.Key + ": " + kv.Value; ;
            }
            foreach (var val in _Positionals)
            {
                if (ret != "")
                {
                    ret += "\n";
                }
                ret += "- " + val;
            }
            return ret;
        }

        public Convertable this[int index]
        {
            get
            {
                return _Positionals[index];
            }
        }

        public Convertable this[string index]
        {
            get
            {
                return _KeyValue[index];
            }
        }

        public int Count
        {
            get
            {
                return _Positionals.Count;
            }
        }

        public class Convertable
        {
            private enum V_Type
            {
                T_int,
                T_string,
                T_double,
                T_float,
                T_bool,
                T_None,
            }

            private int _val_i = 0;
            private float _val_f = 0.0F;
            private double _val_d = 0.0;
            private string _val_s = "";
            private bool _val_b = true;
            private V_Type type = V_Type.T_None;

            public override string ToString()
            {
                if (type == V_Type.T_int)
                {
                    return _val_i.ToString();
                }
                else if (type == V_Type.T_string)
                {
                    return _val_s;
                }
                else if (type == V_Type.T_double)
                {
                    return _val_d.ToString();
                }
                else if (type == V_Type.T_float)
                {
                    return _val_f.ToString();
                }
                else if (type == V_Type.T_bool)
                {
                    return _val_b.ToString();
                }
                else
                {
                    return "";
                }
            }

            public bool isNone
            {
                get
                {
                    return type == V_Type.T_None;
                }
            }

            private Convertable(int v)
            {
                type = V_Type.T_int;
                _val_i = v;
            }

            private Convertable(string v)
            {
                type = V_Type.T_string;
                _val_s = v;
            }

            private Convertable(float v)
            {
                type = V_Type.T_float;
                _val_f = v;
            }
            private Convertable(double v)
            {
                type = V_Type.T_double;
                _val_d = v;
            }

            private Convertable(bool b)
            {
                type = V_Type.T_bool;
                _val_b = b;
            }

            private Convertable()
            {
                type = V_Type.T_None;

            }

            public static implicit operator int(Convertable target)
            {
                if (target.type != V_Type.T_int)
                {
                    throw new Exception();
                }
                return target._val_i;
            }

            public static implicit operator float(Convertable target)
            {
                if (target.type != V_Type.T_float)
                {
                    throw new Exception();
                }
                return target._val_f;
            }

            public static implicit operator double(Convertable target)
            {
                if (target.type != V_Type.T_double)
                {
                    throw new Exception();
                }
                return target._val_d;
            }

            public static implicit operator string(Convertable target)
            {
                if (target.type != V_Type.T_string)
                {
                    throw new Exception();
                }
                return target._val_s;
            }

            public static implicit operator bool(Convertable target)
            {
                if (target.type != V_Type.T_bool)
                {
                    throw new Exception();
                }
                return target._val_b;
            }

            public static implicit operator Convertable(int target)
            {
                return new Convertable(target);
            }

            public static implicit operator Convertable(float target)
            {
                return new Convertable(target);
            }

            public static implicit operator Convertable(double target)
            {
                return new Convertable(target);
            }

            public static implicit operator Convertable(string? target)
            {
                if (target == null)
                {
                    return new Convertable();
                }
                return new Convertable(target);
            }

            public static implicit operator Convertable(bool target)
            {
                return new Convertable(target);
            }
        }
    }
}