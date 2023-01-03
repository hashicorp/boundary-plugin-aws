// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

// getOpts iterates the inbound Options and returns a struct
func getOpts(opt ...Option) (options, error) {
	opts := getDefaultOptions()
	for _, o := range opt {
		if o == nil {
			continue
		}
		if err := o(&opts); err != nil {
			return options{}, err
		}
	}
	return opts, nil
}

// Option - how Options are passed as arguments
type Option func(*options) error

// options = how options are represented
type options struct {
	withRegion string
}

func getDefaultOptions() options {
	return options{}
}

// WithRegion contains the region to use
func WithRegion(with string) Option {
	return func(o *options) error {
		o.withRegion = with
		return nil
	}
}
