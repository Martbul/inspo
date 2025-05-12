package flags

import (
	"flag"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// FlagMakingOptions control the way FlagMaker's behavior when defining flags.
type FlagMakingOptions struct {
	// Use lower case flag names rather than the field name/tag name directly.
	UseLowerCase bool
	// Create flags in namespaced fashion
	Flatten bool
	// If there is a struct tag named 'TagName', use its value as the flag name.
	// The purpose is that, for yaml/json parsing we often have something like
	// Foobar string `yaml:"host_name"`, in which case the flag will be named
	// 'host_name' rather than 'foobar'.
	TagName string
	// If there is a struct tag named 'TagUsage', use its value as the usage description.
	TagUsage string
}

// FlagMaker enumerate all the exported fields of a struct recursively
// and create corresponding command line flags. For anonymous fields,
// they are only enumerated if they are pointers to structs.
// Usual GoLang flag rules apply, e.g. duplicated flag names leads to
// panic.
type FlagMaker struct {
	opts *FlagMakingOptions
	// We don't consume os.Args directly unless told to.
	fs *flag.FlagSet
}

// NewFlagMaker creates a default FlagMaker which creates namespaced flags
func NewFlagMaker() *FlagMaker {
	return NewFlagMakerAdv(&FlagMakingOptions{
		UseLowerCase: true,
		Flatten:      false,
		TagName:      "yaml",
		TagUsage:     "usage"})
}

// NewFlagMakerAdv gives full control to create flags.
func NewFlagMakerAdv(options *FlagMakingOptions) *FlagMaker {
	return &FlagMaker{
		opts: options,
		fs:   flag.NewFlagSet("xFlags", flag.ContinueOnError),
	}
}

func NewFlagMakerFlagSet(options *FlagMakingOptions, fs *flag.FlagSet) *FlagMaker {
	return &FlagMaker{
		opts: options,
		fs:   fs,
	}
}

func ParseArgs(obj interface{}, args []string) ([]string, error) {
	fm := NewFlagMaker()
	return fm.ParseArgs(obj, args)
}

// PrintDefaults prints the default value and type of defined flags.
// It just calls the standard 'flag' package's PrintDefaults.
func (fm *FlagMaker) PrintDefaults() {
	fm.fs.PrintDefaults()
}

// ParseArgs parses the arguments based on the FlagMaker's setting.
func (fm *FlagMaker) ParseArgs(obj interface{}, args []string) ([]string, error) {
	v := reflect.ValueOf(obj)

	if v.Kind() != reflect.Ptr {
		return args, fmt.Errorf("top level object must be a pointer. %v is passed", v.Type())
	}

	if v.IsNil() {
		return args, fmt.Errorf("top level object cannot be nil")
	}

	switch e := v.Elem(); e.Kind() {
	case reflect.Struct:
		fm.enumerateAndCreate("", e, "")
	case reflect.Interface:
		if e.Elem().Kind() == reflect.Ptr {
			fm.enumerateAndCreate("", e, "")
		} else {
			return args, fmt.Errorf("interface must have pointer underlying type. %v is passed", v.Type())
		}
	default:
		return args, fmt.Errorf("object must be a pointer to struct or interface. %v is passed", v.Type())
	}

	err := fm.fs.Parse(args)
	return fm.fs.Args(), err
}

func (fm *FlagMaker) enumerateAndCreate(prefix string, value reflect.Value, usage string) {
	switch value.Kind() {
	case
		// do no create flag for these types
		reflect.Map,
		reflect.Uintptr,
		reflect.UnsafePointer,
		reflect.Array,
		reflect.Chan,
		reflect.Func:
		return
	case reflect.Slice:
		// only support slice of strings, ints and float64s
		switch value.Type().Elem().Kind() {
		case reflect.String:
			fm.defineStringSlice(prefix, value, usage)
		case reflect.Int:
			fm.defineIntSlice(prefix, value, usage)
		case reflect.Float64:
			fm.defineFloat64Slice(prefix, value, usage)
		}
		return
	case
		// Basic value types
		reflect.String,
		reflect.Bool,
		reflect.Float32, reflect.Float64,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		fm.defineFlag(prefix, value, usage)
		return
	case reflect.Interface:
		if !value.IsNil() {
			fm.enumerateAndCreate(prefix, value.Elem(), usage)
		}
		return
	case reflect.Ptr:
		if value.IsNil() {
			value.Set(reflect.New(value.Type().Elem()))
		}
		fm.enumerateAndCreate(prefix, value.Elem(), usage)
		return
	case reflect.Struct:
		// keep going
	default:
		panic(fmt.Sprintf("unknown reflected kind %v", value.Kind()))
	}

	numFields := value.NumField()
	tt := value.Type()

	for i := 0; i < numFields; i++ {
		stField := tt.Field(i)
		// Skip unexported fields, as only exported fields can be set. This is similar to how json and yaml work.
		if stField.PkgPath != "" && !stField.Anonymous {
			continue
		}
		if stField.Anonymous && fm.getUnderlyingType(stField.Type).Kind() != reflect.Struct {
			continue
		}
		field := value.Field(i)
		optName := fm.getName(stField)
		if len(prefix) > 0 && !fm.opts.Flatten {
			optName = prefix + "." + optName
		}

		usageDesc := fm.getUsage(optName, stField)
		//if len(usageDesc) == 0 {
		//	optName = optName
		//}

		fm.enumerateAndCreate(optName, field, usageDesc)
	}
}

func (fm *FlagMaker) getName(field reflect.StructField) string {
	name := field.Tag.Get(fm.opts.TagName)
	if len(name) == 0 {
		if field.Anonymous {
			name = fm.getUnderlyingType(field.Type).Name()
		} else {
			name = field.Name
		}
	}
	if fm.opts.UseLowerCase {
		return strings.ToLower(name)
	}
	return name
}

func (fm *FlagMaker) getUsage(name string, field reflect.StructField) string {
	usage := field.Tag.Get(fm.opts.TagUsage)
	if len(usage) == 0 {
		usage = name
	}
	return usage
}

func (fm *FlagMaker) getUnderlyingType(ttype reflect.Type) reflect.Type {
	// this only deals with *T unnamed type, other unnamed types, e.g. []int, struct{}
	// will return empty string.
	if ttype.Kind() == reflect.Ptr {
		return fm.getUnderlyingType(ttype.Elem())
	}
	return ttype
}

// Each object has its type (which prescribes the possible operations/methods
// could be invoked; it also has an underlying 'kind', int, float, struct etc.
// Since user can freely define types, one 'kind' of object may correpond to
// many types. We cannot do type assertion because types of same kind are still
// different types. Instead, we convert to the primitive types that corresponds
// to the kinds and create flag vars. One thing to know is that, the whole point
// of defineFlag() method is to define flag.Vars that points to certain field
// of the struct so that command line values can modify the struct. We cannot
// define a flag var pointing to arbitrary 'free' varible.

// I wish GoLang had macro...
var (
	stringPtrType  = reflect.TypeOf((*string)(nil))
	boolPtrType    = reflect.TypeOf((*bool)(nil))
	float32PtrType = reflect.TypeOf((*float32)(nil))
	float64PtrType = reflect.TypeOf((*float64)(nil))
	intPtrType     = reflect.TypeOf((*int)(nil))
	int8PtrType    = reflect.TypeOf((*int8)(nil))
	int16PtrType   = reflect.TypeOf((*int16)(nil))
	int32PtrType   = reflect.TypeOf((*int32)(nil))
	int64PtrType   = reflect.TypeOf((*int64)(nil))
	uintPtrType    = reflect.TypeOf((*uint)(nil))
	uint8PtrType   = reflect.TypeOf((*uint8)(nil))
	uint16PtrType  = reflect.TypeOf((*uint16)(nil))
	uint32PtrType  = reflect.TypeOf((*uint32)(nil))
	uint64PtrType  = reflect.TypeOf((*uint64)(nil))
)

func (fm *FlagMaker) defineFlag(name string, value reflect.Value, usage string) {
	// v must be scalar, otherwise panic
	ptrValue := value.Addr()
	switch value.Kind() {
	case reflect.String:
		v := ptrValue.Convert(stringPtrType).Interface().(*string)
		fm.fs.StringVar(v, name, value.String(), usage)
	case reflect.Bool:
		v := ptrValue.Convert(boolPtrType).Interface().(*bool)
		fm.fs.BoolVar(v, name, value.Bool(), usage)
	case reflect.Int:
		v := ptrValue.Convert(intPtrType).Interface().(*int)
		fm.fs.IntVar(v, name, int(value.Int()), usage)
	case reflect.Int8:
		v := ptrValue.Convert(int8PtrType).Interface().(*int8)
		fm.fs.Var(newInt8Value(v), name, usage)
	case reflect.Int16:
		v := ptrValue.Convert(int16PtrType).Interface().(*int16)
		fm.fs.Var(newInt16Value(v), name, usage)
	case reflect.Int32:
		v := ptrValue.Convert(int32PtrType).Interface().(*int32)
		fm.fs.Var(newInt32Value(v), name, usage)
	case reflect.Int64:
		switch v := ptrValue.Interface().(type) {
		case *int64:
			fm.fs.Int64Var(v, name, value.Int(), usage)
		case *time.Duration:
			fm.fs.DurationVar(v, name, value.Interface().(time.Duration), usage)
		default:
			// (TODO) if one type defines time.Duration, we'll create a int64 flag for it.
			// Find some acceptable way to deal with it.
			vv := ptrValue.Convert(int64PtrType).Interface().(*int64)
			fm.fs.Int64Var(vv, name, value.Int(), usage)
		}
	case reflect.Float32:
		v := ptrValue.Convert(float32PtrType).Interface().(*float32)
		fm.fs.Var(newFloat32Value(v), name, usage)
	case reflect.Float64:
		v := ptrValue.Convert(float64PtrType).Interface().(*float64)
		fm.fs.Float64Var(v, name, value.Float(), usage)
	case reflect.Uint:
		v := ptrValue.Convert(uintPtrType).Interface().(*uint)
		fm.fs.UintVar(v, name, uint(value.Uint()), usage)
	case reflect.Uint8:
		v := ptrValue.Convert(uint8PtrType).Interface().(*uint8)
		fm.fs.Var(newUint8Value(v), name, usage)
	case reflect.Uint16:
		v := ptrValue.Convert(uint16PtrType).Interface().(*uint16)
		fm.fs.Var(newUint16Value(v), name, usage)
	case reflect.Uint32:
		v := ptrValue.Convert(uint32PtrType).Interface().(*uint32)
		fm.fs.Var(newUint32Value(v), name, usage)
	case reflect.Uint64:
		v := ptrValue.Convert(uint64PtrType).Interface().(*uint64)
		fm.fs.Uint64Var(v, name, value.Uint(), usage)
	}
}

func (fm *FlagMaker) defineStringSlice(name string, value reflect.Value, usage string) {
	ptrValue := value.Addr().Interface().(*[]string)
	fm.fs.Var(newStringSlice(ptrValue), name, usage)
}

func (fm *FlagMaker) defineIntSlice(name string, value reflect.Value, usage string) {
	ptrValue := value.Addr().Interface().(*[]int)
	fm.fs.Var(newIntSlice(ptrValue), name, usage)
}

func (fm *FlagMaker) defineFloat64Slice(name string, value reflect.Value, usage string) {
	ptrValue := value.Addr().Interface().(*[]float64)
	fm.fs.Var(newFloat64Slice(ptrValue), name, usage)
}
