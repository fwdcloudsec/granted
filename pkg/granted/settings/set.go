package settings

import (
	"fmt"
	"reflect"
	"strconv"

	"github.com/AlecAivazis/survey/v2"
	"github.com/common-fate/clio"
	"github.com/common-fate/grab"
	"github.com/fwdcloudsec/granted/pkg/config"
	"github.com/urfave/cli/v2"
)

var SetConfigCommand = cli.Command{
	Name:  "set",
	Usage: "Set a value in settings",
	Flags: []cli.Flag{
		&cli.StringFlag{Name: "setting", Aliases: []string{"s"}, Usage: "The name of a configuration setting, currently only string, int and bool types are supported. e.g 'DisableUsageTips'. For other configuration, set the value using builtin commands or by directly modifying the config file for advanced use cases."},
		&cli.StringFlag{Name: "value", Aliases: []string{"v"}, Usage: "The value to set the configuration setting to"},
	},
	Action: func(c *cli.Context) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}

		fieldMap := FieldOptions(cfg)

		if cfg.Keyring == nil {
			cfg.Keyring = &config.KeyringConfig{}
		}

		// custom mapping for the keychain fields because the field options generator doesn;t work for nillable fields
		fieldMap["Keyring.Backend"] = keyringFields{&cfg.Keyring.Backend}
		fieldMap["Keyring.KeychainName"] = keyringFields{&cfg.Keyring.KeychainName}
		fieldMap["Keyring.FileDir"] = keyringFields{&cfg.Keyring.FileDir}
		fieldMap["Keyring.LibSecretCollectionName"] = keyringFields{&cfg.Keyring.LibSecretCollectionName}
		fieldMap["Keyring.PassDir"] = keyringFields{&cfg.Keyring.PassDir}

		fields := make([]string, 0, len(fieldMap))
		for k := range fieldMap {
			fields = append(fields, k)
		}

		var selectedFieldName = c.String("setting")
		if selectedFieldName == "" {
			p := &survey.Select{
				Message: "Select the configuration to change",
				Options: fields,
			}
			err = survey.AskOne(p, &selectedFieldName)
			if err != nil {
				return err
			}
		}

		var ok bool
		selectedField, ok := fieldMap[selectedFieldName]
		if !ok {
			return fmt.Errorf("the selected field %s is not a valid config parameter", selectedFieldName)
		}
		// Prompt the user to update the field
		var value interface{}
		var prompt survey.Prompt

		switch selectedField.Kind() {
		case reflect.Bool:
			if !c.IsSet("value") {
				prompt = &survey.Confirm{
					Message: fmt.Sprintf("Enter new value for %s:", selectedFieldName),
					Default: selectedField.Value().(bool),
				}
				err = survey.AskOne(prompt, &value)
				if err != nil {
					return err
				}
			} else {
				valueStr := c.String("value")
				value, err = strconv.ParseBool(valueStr)
				if err != nil {
					return err
				}
			}

		case reflect.String:
			if !c.IsSet("value") {
				var str string
				prompt = &survey.Input{
					Message: fmt.Sprintf("Enter new value for %s:", selectedFieldName),
					Default: selectedField.Value().(string),
				}
				err = survey.AskOne(prompt, &str)
				if err != nil {
					return err
				}
				value = str
			} else {
				value = c.String("value")
			}
		case reflect.Int:
			if !c.IsSet("value") {
				prompt = &survey.Input{
					Message: fmt.Sprintf("Enter new value for %s:", selectedFieldName),
					Default: fmt.Sprintf("%v", selectedField.Value()),
				}
				err = survey.AskOne(prompt, &value)
				if err != nil {
					return err
				}
			} else {
				valueInt := c.String("value")
				value, err = strconv.Atoi(valueInt)
				if err != nil {
					return err
				}
			}
		}

		err = selectedField.Set(value)
		if err != nil {
			return err
		}

		clio.Infof("Updating the value of %s to %v", selectedFieldName, value)
		err = cfg.Save()
		if err != nil {
			return err
		}
		clio.Success("Config updated successfully")
		return nil
	},
}

type Field interface {
	Set(value any) error
	Value() any
	Kind() reflect.Kind
}

type keyringFields struct {
	// double pointer here is a pointer to a pointer value in the config
	// so that we can initialise it if it is unset
	field **string
}

func (f keyringFields) Set(value any) error {
	if *f.field == nil {
		*f.field = new(string)
	}
	**f.field = value.(string)
	return nil
}
func (f keyringFields) Value() any {
	return grab.Value(grab.Value(f.field))
}
func (f keyringFields) Kind() reflect.Kind {
	return reflect.String
}

type field struct {
	ftype  reflect.StructField
	fvalue reflect.Value
}

func (f field) Set(value any) error {
	// Set the new value for the field
	newValue := reflect.ValueOf(value)
	if newValue.Type().ConvertibleTo(f.ftype.Type) {
		f.fvalue.Set(newValue.Convert(f.ftype.Type))
	} else {
		return fmt.Errorf("invalid type for %s", f.ftype.Name)
	}
	return nil
}
func (f field) Value() any {
	return f.fvalue.Interface()
}
func (f field) Kind() reflect.Kind {
	return f.ftype.Type.Kind()
}

// FieldOptions doesn't handle setting nillable fields with no existing value
// for the keychain, we have a customer mapping to set those
func FieldOptions(cfg any) map[string]Field {
	// Get the type and value of the Config struct
	configType := reflect.TypeOf(cfg)
	configValue := reflect.ValueOf(cfg)

	// Check if cfg is a pointer to a struct
	if configType.Kind() == reflect.Ptr && configType.Elem().Kind() == reflect.Struct {
		configType = configType.Elem()
		configValue = configValue.Elem()
	} else if configType.Kind() != reflect.Struct {
		// cfg is neither a struct nor a pointer to a struct
		return nil
	}

	var fieldMap = make(map[string]Field)

	//traverseConfigFields goes through all config variables taking note of each of the types and saves them to the fieldmap
	//In the case where there are sub fields in the toml config, it is recursively called to traverse the sub config
	var traverseConfigFields func(reflect.Type, reflect.Value, string)
	traverseConfigFields = func(t reflect.Type, v reflect.Value, parent string) {
		for i := 0; i < t.NumField(); i++ {
			fieldType := t.Field(i)
			fieldValue := v.Field(i)
			kind := fieldType.Type.Kind()
			fieldName := fieldType.Name
			if parent != "" {
				fieldName = parent + "." + fieldType.Name
			}

			//subfield structs reflect as a pointer
			if kind == reflect.Ptr {
				// Dereference the pointer to get the underlying value
				if !fieldValue.IsNil() {
					fieldValue = fieldValue.Elem()
					kind = fieldValue.Kind()
				}
			}

			switch kind {
			case reflect.Bool, reflect.String, reflect.Int:
				fieldMap[fieldName] = field{
					ftype:  fieldType,
					fvalue: fieldValue,
				}
			case reflect.Struct:
				traverseConfigFields(fieldValue.Type(), fieldValue, fieldName)
			}
		}
	}
	traverseConfigFields(configType, configValue, "")

	return fieldMap
}
